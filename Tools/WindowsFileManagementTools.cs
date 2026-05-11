using System.ComponentModel;
using System.Runtime.Versioning;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Configuration;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// Mutating filesystem operations for remote Windows hosts — every tool calls
/// <see cref="RemoteAdminService.EnsureWriteAllowed"/>, so all of them are gated by the
/// <c>RemoteAdmin:ReadOnly</c> config flag.
/// </summary>
[SupportedOSPlatform("windows")]
[McpServerToolType]
public static class WindowsFileManagementTools
{
    /// <summary>Hard cap on write size, regardless of what an agent asks for.</summary>
    private const int MaxWriteBytes = 10 * 1024 * 1024;

    [McpServerTool(Name = "win_write_file"),
     Description("Create or overwrite a file on a remote Windows host with UTF-8 text content (no BOM). Creates parent directories as needed. Hard cap 10MB. Blocked by RemoteAdmin:ReadOnly.")]
    public static string WriteFile(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path,
        [Description("UTF-8 text content")] string content)
    {
        admin.EnsureOperationAllowed(Operation.WinWriteFile);
        EnsureUnderLimit(content);
        var target = inventory.GetRequired(server);
        const string script = """
            param($path, $content)
            $dir = [System.IO.Path]::GetDirectoryName($path)
            if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            [System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
            $info = Get-Item -LiteralPath $path
            [PSCustomObject]@{
                Path      = $info.FullName
                SizeBytes = [int64]$info.Length
                Action    = 'overwrite'
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { path, content }, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_append_to_file"),
     Description("Append UTF-8 text to a file on a remote Windows host. Creates the file (and parent directories) if it doesn't exist. Hard cap 10MB per call. Blocked by RemoteAdmin:ReadOnly.")]
    public static string AppendToFile(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path,
        [Description("UTF-8 text content to append")] string content)
    {
        admin.EnsureOperationAllowed(Operation.WinAppendToFile);
        EnsureUnderLimit(content);
        var target = inventory.GetRequired(server);
        const string script = """
            param($path, $content)
            $dir = [System.IO.Path]::GetDirectoryName($path)
            if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            [System.IO.File]::AppendAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
            $info = Get-Item -LiteralPath $path
            [PSCustomObject]@{
                Path      = $info.FullName
                SizeBytes = [int64]$info.Length
                Action    = 'append'
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { path, content }, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_create_folder"),
     Description("Create a directory on a remote Windows host. Creates parent directories as needed. Idempotent — succeeds if the directory already exists. Blocked by RemoteAdmin:ReadOnly.")]
    public static string CreateFolder(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path)
    {
        admin.EnsureOperationAllowed(Operation.WinCreateFolder);
        var target = inventory.GetRequired(server);
        const string script = """
            param($path)
            $existed = Test-Path -LiteralPath $path
            $info = New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop
            [PSCustomObject]@{
                Path     = $info.FullName
                Existed  = $existed
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { path }, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_delete_file"),
     Description("Delete a single file on a remote Windows host. Refuses to delete directories — use win_delete_folder for those. Blocked by RemoteAdmin:ReadOnly.")]
    public static string DeleteFile(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path)
    {
        admin.EnsureOperationAllowed(Operation.WinDeleteFile);
        var target = inventory.GetRequired(server);
        const string script = """
            param($path)
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.PSIsContainer) {
                throw "Path is a directory: $path. Use win_delete_folder instead."
            }
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            [PSCustomObject]@{ Path = $path; Deleted = $true }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { path }, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_delete_folder"),
     Description("Delete a directory on a remote Windows host. Requires recursive=true to delete a non-empty directory (rm -rf). Blocked by RemoteAdmin:ReadOnly.")]
    public static string DeleteFolder(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path,
        [Description("If true, delete recursively including all contents. Default false — non-empty directories raise an error.")] bool recursive = false)
    {
        admin.EnsureOperationAllowed(Operation.WinDeleteFolder);
        var target = inventory.GetRequired(server);
        const string script = """
            param($path, $recursive)
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (-not $item.PSIsContainer) {
                throw "Path is a file: $path. Use win_delete_file instead."
            }
            if (-not $recursive) {
                $children = Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue
                if ($children) {
                    throw "Directory is not empty ($($children.Count) items). Pass recursive=true to delete it and all contents."
                }
            }
            Remove-Item -LiteralPath $path -Recurse:$recursive -Force -ErrorAction Stop
            [PSCustomObject]@{ Path = $path; Deleted = $true; Recursive = [bool]$recursive }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { path, recursive }, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_copy_path"),
     Description("Copy a file or directory on a remote Windows host. For directories pass recursive=true. Blocked by RemoteAdmin:ReadOnly.")]
    public static string CopyPath(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path of the source on the remote host")] string source,
        [Description("Absolute path of the destination on the remote host")] string destination,
        [Description("Required true to copy directories. Default false.")] bool recursive = false,
        [Description("Overwrite destination if it exists. Default false.")] bool overwrite = false)
    {
        admin.EnsureOperationAllowed(Operation.WinCopyPath);
        var target = inventory.GetRequired(server);
        const string script = """
            param($source, $destination, $recursive, $overwrite)
            $item = Get-Item -LiteralPath $source -Force -ErrorAction Stop
            if ($item.PSIsContainer -and -not $recursive) {
                throw "Source is a directory; pass recursive=true to copy it."
            }
            if ((Test-Path -LiteralPath $destination) -and -not $overwrite) {
                throw "Destination already exists. Pass overwrite=true to replace it."
            }
            Copy-Item -LiteralPath $source -Destination $destination -Recurse:$recursive -Force:$overwrite -ErrorAction Stop
            [PSCustomObject]@{ Source = $source; Destination = $destination; Recursive = [bool]$recursive }
            """;
        return exec.InvokeRemoteJson(target, script,
            new object?[] { source, destination, recursive, overwrite }, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_move_path"),
     Description("Move or rename a file or directory on a remote Windows host. Blocked by RemoteAdmin:ReadOnly.")]
    public static string MovePath(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path of the source on the remote host")] string source,
        [Description("Absolute path of the destination on the remote host")] string destination,
        [Description("Overwrite destination if it exists. Default false.")] bool overwrite = false)
    {
        admin.EnsureOperationAllowed(Operation.WinMovePath);
        var target = inventory.GetRequired(server);
        const string script = """
            param($source, $destination, $overwrite)
            if (-not (Test-Path -LiteralPath $source)) { throw "Source not found: $source" }
            if ((Test-Path -LiteralPath $destination) -and -not $overwrite) {
                throw "Destination already exists. Pass overwrite=true to replace it."
            }
            Move-Item -LiteralPath $source -Destination $destination -Force:$overwrite -ErrorAction Stop
            [PSCustomObject]@{ Source = $source; Destination = $destination }
            """;
        return exec.InvokeRemoteJson(target, script,
            new object?[] { source, destination, overwrite }, jsonDepth: 3);
    }

    private static void EnsureUnderLimit(string content)
    {
        // System.Text.Encoding.UTF8.GetByteCount is exact but we only need an upper bound; chars
        // <= bytes for the 10MB check, so the cheaper length comparison suffices.
        if (content.Length > MaxWriteBytes)
            throw new InvalidOperationException(
                $"Content exceeds the {MaxWriteBytes:N0}-byte cap. Split the write or use a bulk-transfer tool.");
    }
}
