using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Configuration;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// Mutating Linux operations over SSH. Every entrypoint must call
/// <see cref="RemoteAdminService.EnsureWriteAllowed"/> before doing anything.
///
/// systemctl normally requires root. Configure passwordless sudo for the SSH user and set
/// <c>useSudo: true</c> in the credentials block — the tool will prepend <c>sudo -n</c>.
/// </summary>
[McpServerToolType]
public static class LinuxManagementTools
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    [McpServerTool(Name = "linux_start_service"),
     Description("Start a systemd service on a remote Linux machine. Blocked by RemoteAdmin:ReadOnly.")]
    public static string StartService(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Systemd unit name, e.g. nginx.service or just nginx")] string serviceName)
    {
        admin.EnsureOperationAllowed(Operation.LinuxStartService);
        return RunSystemctl(inventory, exec, server, serviceName, "start");
    }

    [McpServerTool(Name = "linux_stop_service"),
     Description("Stop a systemd service on a remote Linux machine. Blocked by RemoteAdmin:ReadOnly.")]
    public static string StopService(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Systemd unit name")] string serviceName)
    {
        admin.EnsureOperationAllowed(Operation.LinuxStopService);
        return RunSystemctl(inventory, exec, server, serviceName, "stop");
    }

    [McpServerTool(Name = "linux_restart_service"),
     Description("Restart a systemd service on a remote Linux machine. Blocked by RemoteAdmin:ReadOnly.")]
    public static string RestartService(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Systemd unit name")] string serviceName)
    {
        admin.EnsureOperationAllowed(Operation.LinuxRestartService);
        return RunSystemctl(inventory, exec, server, serviceName, "restart");
    }

    [McpServerTool(Name = "linux_kill_process"),
     Description("Send a signal to a process on a remote Linux machine (default SIGTERM=15). Blocked by RemoteAdmin:ReadOnly.")]
    public static string KillProcess(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Target pid")] int processId,
        [Description("Signal number (default 15 = SIGTERM). Use 9 for SIGKILL.")] int signal = 15)
    {
        admin.EnsureOperationAllowed(Operation.LinuxKillProcess);
        var target = inventory.GetRequired(server);
        var prefix = (target.Credentials?.UseSudo ?? false) ? "sudo -n " : "";
        var command = $"{prefix}kill -{signal} {processId}";
        var result = exec.InvokeRemoteOrThrow(target, command);
        return JsonSerializer.Serialize(new
        {
            ProcessId = processId,
            Signal = signal,
            ExitCode = result.ExitCode,
            StdOut = result.StdOut,
            StdErr = result.StdErr,
        }, JsonOpts);
    }

    private static string RunSystemctl(
        ServerInventoryService inventory,
        SshRemoteExecutor exec,
        string server,
        string serviceName,
        string action)
    {
        var target = inventory.GetRequired(server);
        var prefix = (target.Credentials?.UseSudo ?? false) ? "sudo -n " : "";
        var command = $"{prefix}systemctl {action} {SshRemoteExecutor.ShellQuote(serviceName)}";
        var result = exec.InvokeRemoteOrThrow(target, command);

        // Follow up with a status read so callers can see whether the action settled.
        var status = exec.InvokeRemote(target,
            $"systemctl is-active {SshRemoteExecutor.ShellQuote(serviceName)}; systemctl is-enabled {SshRemoteExecutor.ShellQuote(serviceName)} 2>/dev/null || true");

        var statusLines = status.StdOut.Trim().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        return JsonSerializer.Serialize(new
        {
            Service = serviceName,
            Action = action,
            ExitCode = result.ExitCode,
            ActiveState = statusLines.Length > 0 ? statusLines[0].Trim() : null,
            EnabledState = statusLines.Length > 1 ? statusLines[1].Trim() : null,
        }, JsonOpts);
    }
}
