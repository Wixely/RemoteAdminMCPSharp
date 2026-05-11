using System.ComponentModel;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Configuration;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// Mutating filesystem operations for remote Linux hosts — every tool calls
/// <see cref="RemoteAdminService.EnsureWriteAllowed"/>, so all of them are gated by the
/// <c>RemoteAdmin:ReadOnly</c> config flag.
///
/// Write/append send the payload base64-encoded inside a single shell argument, which keeps us
/// well under typical ARG_MAX (128KB+). The cap is therefore 64KB per call. For bulk transfers
/// you'd want a future SFTP-based tool — call it out so the operator knows the boundary.
/// </summary>
[McpServerToolType]
public static class LinuxFileManagementTools
{
    /// <summary>Inline-base64 transfers have to fit under ARG_MAX. 64KB content → ~87KB base64.</summary>
    private const int MaxWriteBytes = 64 * 1024;

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    [McpServerTool(Name = "linux_write_file"),
     Description("Create or overwrite a file on a remote Linux host with UTF-8 text content. Creates parent directories if needed. Hard cap 64KB per call (inline base64 transfer). Blocked by RemoteAdmin:ReadOnly.")]
    public static string WriteFile(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path,
        [Description("UTF-8 text content")] string content)
    {
        admin.EnsureOperationAllowed(Operation.LinuxWriteFile);
        var target = inventory.GetRequired(server);
        return WriteOrAppend(target, exec, path, content, append: false, "overwrite");
    }

    [McpServerTool(Name = "linux_append_to_file"),
     Description("Append UTF-8 text to a file on a remote Linux host. Creates the file (and parent directories) if it doesn't exist. Hard cap 64KB per call. Blocked by RemoteAdmin:ReadOnly.")]
    public static string AppendToFile(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path,
        [Description("UTF-8 text content to append")] string content)
    {
        admin.EnsureOperationAllowed(Operation.LinuxAppendToFile);
        var target = inventory.GetRequired(server);
        return WriteOrAppend(target, exec, path, content, append: true, "append");
    }

    [McpServerTool(Name = "linux_create_folder"),
     Description("Create a directory on a remote Linux host (mkdir -p). Creates parents as needed, idempotent. Blocked by RemoteAdmin:ReadOnly.")]
    public static string CreateFolder(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path)
    {
        admin.EnsureOperationAllowed(Operation.LinuxCreateFolder);
        var target = inventory.GetRequired(server);
        var qPath = SshRemoteExecutor.ShellQuote(path);
        exec.InvokeRemoteOrThrow(target, $"mkdir -p {qPath}");
        return JsonSerializer.Serialize(new { Path = path, Action = "create" }, JsonOpts);
    }

    [McpServerTool(Name = "linux_delete_file"),
     Description("Delete a single file on a remote Linux host. Refuses to delete directories — use linux_delete_folder. Blocked by RemoteAdmin:ReadOnly.")]
    public static string DeleteFile(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path)
    {
        admin.EnsureOperationAllowed(Operation.LinuxDeleteFile);
        var target = inventory.GetRequired(server);
        var qPath = SshRemoteExecutor.ShellQuote(path);
        // Guard against accidentally rm'ing a directory; surface a clear error otherwise.
        var command =
            $"if [ ! -e {qPath} ]; then echo 'NOT_FOUND' >&2; exit 3; fi; " +
            $"if [ -d {qPath} ]; then echo 'IS_DIRECTORY' >&2; exit 4; fi; " +
            $"rm -f {qPath}";
        exec.InvokeRemoteOrThrow(target, command);
        return JsonSerializer.Serialize(new { Path = path, Deleted = true }, JsonOpts);
    }

    [McpServerTool(Name = "linux_delete_folder"),
     Description("Delete a directory on a remote Linux host. Requires recursive=true to delete a non-empty directory (rm -rf). Blocked by RemoteAdmin:ReadOnly.")]
    public static string DeleteFolder(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path,
        [Description("If true, delete recursively including all contents. Default false — non-empty directories raise an error.")] bool recursive = false)
    {
        admin.EnsureOperationAllowed(Operation.LinuxDeleteFolder);
        var target = inventory.GetRequired(server);
        var qPath = SshRemoteExecutor.ShellQuote(path);
        var command = recursive
            ? $"if [ ! -d {qPath} ]; then echo 'NOT_A_DIRECTORY' >&2; exit 4; fi; rm -rf {qPath}"
            // rmdir only succeeds on an empty directory — perfect natural fit for the safe path.
            : $"if [ ! -d {qPath} ]; then echo 'NOT_A_DIRECTORY' >&2; exit 4; fi; rmdir {qPath}";
        exec.InvokeRemoteOrThrow(target, command);
        return JsonSerializer.Serialize(new { Path = path, Deleted = true, Recursive = recursive }, JsonOpts);
    }

    [McpServerTool(Name = "linux_copy_path"),
     Description("Copy a file or directory on a remote Linux host. For directories pass recursive=true. Blocked by RemoteAdmin:ReadOnly.")]
    public static string CopyPath(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path of the source on the remote host")] string source,
        [Description("Absolute path of the destination on the remote host")] string destination,
        [Description("Required true to copy directories. Default false.")] bool recursive = false,
        [Description("Overwrite destination if it exists. Default false.")] bool overwrite = false)
    {
        admin.EnsureOperationAllowed(Operation.LinuxCopyPath);
        var target = inventory.GetRequired(server);
        var qSrc = SshRemoteExecutor.ShellQuote(source);
        var qDst = SshRemoteExecutor.ShellQuote(destination);
        // cp flags: -r recursive, -n no-clobber (refuse to overwrite). We invert -n based on overwrite.
        var flags = new StringBuilder();
        if (recursive) flags.Append("-r ");
        if (!overwrite) flags.Append("-n ");
        else flags.Append("-f ");
        // -n suppresses the error when the destination exists, so we check ourselves for a clear msg.
        var preCheck = overwrite
            ? ""
            : $"if [ -e {qDst} ]; then echo 'DEST_EXISTS' >&2; exit 5; fi; ";
        var srcCheck = recursive
            ? $"if [ ! -e {qSrc} ]; then echo 'SOURCE_NOT_FOUND' >&2; exit 3; fi; "
            : $"if [ ! -f {qSrc} ]; then echo 'SOURCE_NOT_A_FILE' >&2; exit 4; fi; ";
        exec.InvokeRemoteOrThrow(target, $"{srcCheck}{preCheck}cp {flags}{qSrc} {qDst}");
        return JsonSerializer.Serialize(new { Source = source, Destination = destination, Recursive = recursive }, JsonOpts);
    }

    [McpServerTool(Name = "linux_move_path"),
     Description("Move or rename a file or directory on a remote Linux host. Blocked by RemoteAdmin:ReadOnly.")]
    public static string MovePath(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path of the source on the remote host")] string source,
        [Description("Absolute path of the destination on the remote host")] string destination,
        [Description("Overwrite destination if it exists. Default false.")] bool overwrite = false)
    {
        admin.EnsureOperationAllowed(Operation.LinuxMovePath);
        var target = inventory.GetRequired(server);
        var qSrc = SshRemoteExecutor.ShellQuote(source);
        var qDst = SshRemoteExecutor.ShellQuote(destination);
        var flags = overwrite ? "-f " : "-n ";
        var preCheck = overwrite
            ? ""
            : $"if [ -e {qDst} ]; then echo 'DEST_EXISTS' >&2; exit 5; fi; ";
        exec.InvokeRemoteOrThrow(target,
            $"if [ ! -e {qSrc} ]; then echo 'SOURCE_NOT_FOUND' >&2; exit 3; fi; {preCheck}mv {flags}{qSrc} {qDst}");
        return JsonSerializer.Serialize(new { Source = source, Destination = destination }, JsonOpts);
    }

    private static string WriteOrAppend(
        Configuration.ResolvedServer target,
        SshRemoteExecutor exec,
        string path,
        string content,
        bool append,
        string action)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        if (bytes.Length > MaxWriteBytes)
        {
            throw new InvalidOperationException(
                $"Content is {bytes.Length:N0} bytes; the inline-base64 transport caps at {MaxWriteBytes:N0} bytes per call. " +
                "Split into multiple appends, or wait for the SFTP-backed bulk transfer tool.");
        }

        var b64 = Convert.ToBase64String(bytes);
        var qPath = SshRemoteExecutor.ShellQuote(path);
        var qB64 = SshRemoteExecutor.ShellQuote(b64);
        var redirect = append ? ">>" : ">";

        // Ensure parent directory exists; then decode + redirect. We use printf instead of echo to
        // avoid trailing newlines that some echo implementations add.
        var command =
            $"mkdir -p \"$(dirname {qPath})\" && " +
            $"printf '%s' {qB64} | base64 -d {redirect} {qPath}";
        exec.InvokeRemoteOrThrow(target, command);

        // Round-trip stat so the caller sees the resulting file size.
        var sizeResult = exec.InvokeRemote(target, $"stat -c '%s' {qPath} 2>/dev/null");
        _ = long.TryParse(sizeResult.StdOut.Trim(), out var size);
        return JsonSerializer.Serialize(new
        {
            Path = path,
            SizeBytes = size,
            Action = action,
        }, JsonOpts);
    }
}
