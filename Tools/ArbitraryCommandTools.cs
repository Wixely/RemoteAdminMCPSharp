using System.ComponentModel;
using System.Runtime.Versioning;
using System.Text.Json;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Configuration;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// Single escape hatch per OS for running arbitrary commands. Both
/// <see cref="Configuration.RemoteAdminOptions.AllowArbitraryCommands"/> AND
/// <see cref="Configuration.RemoteAdminOptions.ReadOnly"/>=false must be set — the operator
/// has to opt in twice.
/// </summary>
[McpServerToolType]
public static class ArbitraryCommandTools
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    [SupportedOSPlatform("windows")]
    [McpServerTool(Name = "win_run_command"),
     Description("Run an arbitrary PowerShell expression on a remote Windows host. Captures stdout, stderr, and $LASTEXITCODE. DISABLED by default — requires RemoteAdmin:AllowArbitraryCommands=true AND RemoteAdmin:ReadOnly=false.")]
    public static string WindowsRunCommand(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("PowerShell expression to evaluate on the remote host. Use cmd /c \"...\" if you need cmd.exe semantics.")] string commandLine)
    {
        admin.EnsureArbitraryAllowed();
        admin.EnsureOperationAllowed(Operation.WinRunCommand);

        var target = inventory.GetRequired(server);
        // 2>&1 / *>&1 funnels error/warning/info streams into the success stream so we get the
        // combined transcript back. Out-String preserves layout for human-friendly output.
        const string script = """
            param($cmd)
            $ErrorActionPreference = 'Continue'
            $output = & { Invoke-Expression $cmd } *>&1 | Out-String
            [PSCustomObject]@{
                Output   = $output
                ExitCode = $LASTEXITCODE
            }
            """;

        var json = exec.InvokeRemoteJson(target, script, new object?[] { commandLine }, jsonDepth: 3);
        return Truncate(admin, json);
    }

    [McpServerTool(Name = "linux_run_command"),
     Description("Run an arbitrary shell command on a remote Linux host. Captures stdout, stderr, and exit code. DISABLED by default — requires RemoteAdmin:AllowArbitraryCommands=true AND RemoteAdmin:ReadOnly=false. The command is passed verbatim to the remote shell — wrap in `bash -c '...'` yourself if you need shell features beyond the SSH server's default exec channel.")]
    public static string LinuxRunCommand(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Shell command to execute. The operator decides whether to prepend sudo.")] string commandLine)
    {
        admin.EnsureArbitraryAllowed();
        admin.EnsureOperationAllowed(Operation.LinuxRunCommand);

        var target = inventory.GetRequired(server);
        var result = exec.InvokeRemote(target, commandLine);
        var json = JsonSerializer.Serialize(new
        {
            ExitCode = result.ExitCode,
            StdOut = result.StdOut,
            StdErr = result.StdErr,
        }, JsonOpts);
        return Truncate(admin, json);
    }

    private static string Truncate(RemoteAdminService admin, string json)
    {
        var limit = admin.Options.ArbitraryCommandOutputCharLimit;
        if (limit <= 0 || json.Length <= limit) return json;
        return JsonSerializer.Serialize(new
        {
            truncated = true,
            originalLength = json.Length,
            limit,
            json = json[..limit],
        });
    }
}
