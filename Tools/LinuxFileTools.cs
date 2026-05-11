using System.ComponentModel;
using System.Globalization;
using System.Text.Json;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// Read-only filesystem tools for remote Linux hosts. Constrained only by the SSH user's access.
/// </summary>
[McpServerToolType]
public static class LinuxFileTools
{
    private const int MaxReadBytes = 10 * 1024 * 1024;
    private const int MaxListRows = 10_000;

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    [McpServerTool(Name = "linux_list_files"),
     Description("List the immediate contents of a directory on a remote Linux host. Uses `find -maxdepth 1` with `-printf` for structured tab-separated output. Hidden files are included; non-recursive.")]
    public static string ListFiles(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host, e.g. /var/log")] string path,
        [Description("Optional shell glob filter, e.g. *.log")] string? pattern = null,
        [Description("Max rows to return. Default 500, hard cap 10000.")] int maxRows = 500)
    {
        var target = inventory.GetRequired(server);
        var top = Math.Clamp(maxRows, 1, MaxListRows);
        // -printf fields: %y=type, %M=symbolic perms, %u=owner, %g=group, %s=size, %T@=mtime
        // epoch, %f=basename. Tab-separated so filenames with spaces stay intact (filenames
        // containing tabs are rare; switch to \x1f if you have to support them).
        var nameFilter = string.IsNullOrWhiteSpace(pattern)
            ? ""
            : $" -name {SshRemoteExecutor.ShellQuote(pattern!)}";
        var command = $"find {SshRemoteExecutor.ShellQuote(path)} -maxdepth 1 -mindepth 1{nameFilter} " +
                      "-printf '%y\\t%M\\t%u\\t%g\\t%s\\t%T@\\t%f\\n' " +
                      $"2>&1 | head -n {top}";
        var result = exec.InvokeRemote(target, command);

        var rows = new List<object>();
        foreach (var raw in result.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = raw.TrimEnd('\r').Split('\t');
            if (parts.Length < 7) continue;
            var type = parts[0];
            var perms = parts[1];
            var owner = parts[2];
            var group = parts[3];
            _ = long.TryParse(parts[4], out var size);
            _ = double.TryParse(parts[5], NumberStyles.Float, CultureInfo.InvariantCulture, out var mtimeEpoch);
            var name = parts[6];

            rows.Add(new
            {
                Name = name,
                Type = type,
                SizeBytes = type == "d" ? (long?)null : size,
                Permissions = perms,
                Owner = owner,
                Group = group,
                ModifiedAtUtc = DateTimeOffset.FromUnixTimeSeconds((long)mtimeEpoch).UtcDateTime.ToString("o"),
            });
        }
        return JsonSerializer.Serialize(rows, JsonOpts);
    }

    [McpServerTool(Name = "linux_read_file"),
     Description("Read up to maxBytes from a file on a remote Linux host, returned as UTF-8 text. Reports the actual file size and a Truncated flag so the agent can paginate via offset. Hard cap 10MB per call. Binary content will arrive mangled — use this for text files.")]
    public static string ReadFile(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path,
        [Description("Max bytes to read. Default 65536 (64KB), hard cap 10MB.")] int maxBytes = 65536,
        [Description("Byte offset to start reading from. Default 0.")] long offset = 0)
    {
        var target = inventory.GetRequired(server);
        var capped = Math.Clamp(maxBytes, 1, MaxReadBytes);
        var startAt = Math.Max(0, offset);
        var qPath = SshRemoteExecutor.ShellQuote(path);

        // One round trip: stat for true size, sentinel, then sliced content.
        // tail -c +N is "start at byte N (1-indexed)"; offset=0 means start at byte 1.
        // For offset=0 we skip tail entirely so head can be killed by SIGPIPE as soon as it has
        // enough — important for large files where we only want the first chunk.
        var sliceCmd = startAt > 0
            ? $"tail -c +{startAt + 1} {qPath} | head -c {capped}"
            : $"head -c {capped} {qPath}";
        var command =
            $"stat -c '%s' {qPath} 2>/dev/null; " +
            $"echo '__CONTENT__'; " +
            sliceCmd;

        var result = exec.InvokeRemote(target, command);

        var sepIndex = result.StdOut.IndexOf("__CONTENT__", StringComparison.Ordinal);
        if (sepIndex < 0)
            throw new InvalidOperationException(
                $"Failed to read file (no sentinel in output). stderr: {result.StdErr}");

        var sizeText = result.StdOut[..sepIndex].Trim();
        _ = long.TryParse(sizeText, out var size);

        // Skip past sentinel + newline.
        var contentStart = sepIndex + "__CONTENT__".Length;
        if (contentStart < result.StdOut.Length && result.StdOut[contentStart] == '\n')
            contentStart++;
        var content = result.StdOut[contentStart..];

        var bytesReturned = content.Length;
        var truncated = startAt + bytesReturned < size;

        return JsonSerializer.Serialize(new
        {
            Path = path,
            SizeBytes = size,
            Offset = startAt,
            BytesReturned = bytesReturned,
            Truncated = truncated,
            Content = content,
        }, JsonOpts);
    }

    [McpServerTool(Name = "linux_file_properties"),
     Description("Get detailed properties for a file or directory on a remote Linux host: type, size, owner/group, permissions (symbolic + octal), inode, hard-link count, and atime/mtime/ctime in ISO-8601 UTC.")]
    public static string FileProperties(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path)
    {
        var target = inventory.GetRequired(server);
        var qPath = SshRemoteExecutor.ShellQuote(path);
        // %F=type description, %s=size, %U=owner, %G=group, %A=symbolic perms, %a=octal perms,
        // %X/%Y/%Z=atime/mtime/ctime epoch, %i=inode, %h=hardlinks. No %n so we don't have to
        // worry about pipes in the filename.
        var result = exec.InvokeRemoteOrThrow(target,
            $"stat -c '%F|%s|%U|%G|%A|%a|%X|%Y|%Z|%i|%h' {qPath}");

        var parts = result.StdOut.TrimEnd('\r', '\n').Split('|');
        if (parts.Length < 11)
            throw new InvalidOperationException($"Unexpected stat output: {result.StdOut}");

        _ = long.TryParse(parts[1], out var size);
        _ = long.TryParse(parts[6], out var atime);
        _ = long.TryParse(parts[7], out var mtime);
        _ = long.TryParse(parts[8], out var ctime);
        _ = long.TryParse(parts[9], out var inode);
        _ = int.TryParse(parts[10], out var links);

        return JsonSerializer.Serialize(new
        {
            Path = path,
            Type = parts[0],                 // e.g. "regular file", "directory", "symbolic link"
            SizeBytes = size,
            Owner = parts[2],
            Group = parts[3],
            PermissionsSymbolic = parts[4],  // rwxr-xr-x
            PermissionsOctal = parts[5],     // 755
            Inode = inode,
            HardLinks = links,
            AccessTimeUtc = DateTimeOffset.FromUnixTimeSeconds(atime).UtcDateTime.ToString("o"),
            ModifyTimeUtc = DateTimeOffset.FromUnixTimeSeconds(mtime).UtcDateTime.ToString("o"),
            ChangeTimeUtc = DateTimeOffset.FromUnixTimeSeconds(ctime).UtcDateTime.ToString("o"),
        }, JsonOpts);
    }
}
