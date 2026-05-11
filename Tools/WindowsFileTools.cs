using System.ComponentModel;
using System.Runtime.Versioning;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// Read-only filesystem tools for remote Windows hosts. None of these mutate state, so they're
/// not gated by <see cref="RemoteAdminService.EnsureWriteAllowed"/> — they're constrained only by
/// whatever the connecting credentials can read.
/// </summary>
[SupportedOSPlatform("windows")]
[McpServerToolType]
public static class WindowsFileTools
{
    /// <summary>Hard cap on read size, regardless of what an agent asks for.</summary>
    private const int MaxReadBytes = 10 * 1024 * 1024;

    /// <summary>Hard cap on list size, regardless of what an agent asks for.</summary>
    private const int MaxListRows = 10_000;

    [McpServerTool(Name = "win_list_files"),
     Description("List the immediate contents of a directory on a remote Windows host. Returns name, type (f/d), size, attributes, Mode string, and creation/write/access timestamps in ISO-8601 UTC. Hidden items included (-Force).")]
    public static string ListFiles(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host, e.g. C:\\Logs")] string path,
        [Description("Optional wildcard filter (PowerShell -Filter syntax), e.g. *.log")] string? pattern = null,
        [Description("Max rows to return. Default 500, hard cap 10000.")] int maxRows = 500)
    {
        var target = inventory.GetRequired(server);
        var top = Math.Clamp(maxRows, 1, MaxListRows);
        const string script = """
            param($path, $pattern, $top)
            $gciArgs = @{ Path = $path; Force = $true; ErrorAction = 'Stop' }
            if ($pattern) { $gciArgs['Filter'] = $pattern }
            Get-ChildItem @gciArgs |
                Select-Object -First $top |
                Select-Object @{Name='Name'; Expression={$_.Name}},
                              @{Name='FullName'; Expression={$_.FullName}},
                              @{Name='Type'; Expression={ if ($_.PSIsContainer) { 'd' } else { 'f' } }},
                              @{Name='SizeBytes'; Expression={ if ($_.PSIsContainer) { $null } else { [int64]$_.Length } }},
                              @{Name='Attributes'; Expression={$_.Attributes.ToString()}},
                              @{Name='Mode'; Expression={$_.Mode}},
                              @{Name='CreationTimeUtc'; Expression={$_.CreationTimeUtc.ToString('o')}},
                              @{Name='LastWriteTimeUtc'; Expression={$_.LastWriteTimeUtc.ToString('o')}},
                              @{Name='LastAccessTimeUtc'; Expression={$_.LastAccessTimeUtc.ToString('o')}}
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { path, pattern, top });
    }

    [McpServerTool(Name = "win_read_file"),
     Description("Read up to maxBytes from a file on a remote Windows host, decoded as UTF-8. Returns the actual file size and a Truncated flag so the agent can paginate via the offset parameter. Hard cap 10MB per call. Binary content will arrive mangled — use this for text files (logs, config).")]
    public static string ReadFile(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path,
        [Description("Max bytes to read. Default 65536 (64KB), hard cap 10MB.")] int maxBytes = 65536,
        [Description("Byte offset to start reading from. Default 0.")] long offset = 0)
    {
        var target = inventory.GetRequired(server);
        var capped = Math.Clamp(maxBytes, 1, MaxReadBytes);
        var startAt = Math.Max(0, offset);
        const string script = """
            param($path, $maxBytes, $offset)
            if (-not (Test-Path -LiteralPath $path)) { throw "Path not found: $path" }
            $info = Get-Item -LiteralPath $path
            if ($info.PSIsContainer) { throw "Path is a directory: $path" }
            $size = [int64]$info.Length
            $start = [Math]::Min([int64]$offset, $size)
            $remaining = $size - $start
            $toRead = [Math]::Min([int64]$maxBytes, $remaining)
            $bytes = New-Object byte[] $toRead
            $read = 0
            $fs = [System.IO.File]::OpenRead($path)
            try {
                $fs.Position = $start
                $read = $fs.Read($bytes, 0, $toRead)
            } finally { $fs.Dispose() }
            [PSCustomObject]@{
                Path          = $path
                SizeBytes     = $size
                Offset        = $start
                BytesReturned = $read
                Truncated     = (($start + $read) -lt $size)
                Content       = [System.Text.Encoding]::UTF8.GetString($bytes, 0, $read)
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { path, capped, startAt }, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_file_properties"),
     Description("Get detailed properties for a file or directory on a remote Windows host: size, attributes, owner, ACL access rules, and creation/write/access timestamps in ISO-8601 UTC.")]
    public static string FileProperties(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Absolute path on the remote host")] string path)
    {
        var target = inventory.GetRequired(server);
        const string script = """
            param($path)
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            $acl = $null
            try { $acl = Get-Acl -LiteralPath $path -ErrorAction Stop } catch { }
            [PSCustomObject]@{
                Name              = $item.Name
                FullName          = $item.FullName
                Type              = if ($item.PSIsContainer) { 'd' } else { 'f' }
                SizeBytes         = if ($item.PSIsContainer) { $null } else { [int64]$item.Length }
                Attributes        = $item.Attributes.ToString()
                CreationTimeUtc   = $item.CreationTimeUtc.ToString('o')
                LastWriteTimeUtc  = $item.LastWriteTimeUtc.ToString('o')
                LastAccessTimeUtc = $item.LastAccessTimeUtc.ToString('o')
                Owner             = if ($acl) { $acl.Owner } else { $null }
                AccessRules       = if ($acl) {
                    $acl.Access | Select-Object @{Name='Identity'; Expression={$_.IdentityReference.Value}},
                                                @{Name='Rights'; Expression={$_.FileSystemRights.ToString()}},
                                                @{Name='Type'; Expression={$_.AccessControlType.ToString()}},
                                                @{Name='IsInherited'; Expression={$_.IsInherited}}
                } else { $null }
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { path }, jsonDepth: 5);
    }
}
