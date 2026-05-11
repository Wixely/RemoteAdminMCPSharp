using System.ComponentModel;
using System.Runtime.Versioning;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Configuration;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// Mutating Windows operations over PowerShell Remoting. Every entrypoint must call
/// <see cref="RemoteAdminService.EnsureWriteAllowed"/> before doing anything.
/// </summary>
[SupportedOSPlatform("windows")]
[McpServerToolType]
public static class WindowsManagementTools
{
    [McpServerTool(Name = "win_start_service"),
     Description("Start a Windows service on a remote machine. Blocked by RemoteAdmin:ReadOnly.")]
    public static string StartService(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Service name (the short Name, not DisplayName)")] string serviceName)
    {
        admin.EnsureOperationAllowed(Operation.WinStartService);
        return RunServiceCommand(inventory, exec, server, serviceName, "Start-Service");
    }

    [McpServerTool(Name = "win_stop_service"),
     Description("Stop a Windows service on a remote machine. Blocked by RemoteAdmin:ReadOnly.")]
    public static string StopService(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Service name (the short Name, not DisplayName)")] string serviceName)
    {
        admin.EnsureOperationAllowed(Operation.WinStopService);
        return RunServiceCommand(inventory, exec, server, serviceName, "Stop-Service -Force");
    }

    [McpServerTool(Name = "win_restart_service"),
     Description("Restart a Windows service on a remote machine. Blocked by RemoteAdmin:ReadOnly.")]
    public static string RestartService(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Service name (the short Name, not DisplayName)")] string serviceName)
    {
        admin.EnsureOperationAllowed(Operation.WinRestartService);
        return RunServiceCommand(inventory, exec, server, serviceName, "Restart-Service -Force");
    }

    [McpServerTool(Name = "win_create_service"),
     Description("Create a new Windows service on a remote machine via New-Service. Required: name + binaryPath. Optional: displayName, description, startupType (Automatic/AutomaticDelayedStart/Manual/Disabled — default Manual), and dependencies (comma-separated service short-names). The new service runs as LocalSystem; for a different account use win_run_command with sc.exe config afterwards. Blocked by RemoteAdmin:Operations:WinCreateService.")]
    public static string CreateService(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Short service name (no spaces; this is the registry key name)")] string serviceName,
        [Description("Absolute path to the service executable, including any args, e.g. \"C:\\Services\\foo.exe --port 80\"")] string binaryPath,
        [Description("Optional human-readable display name")] string? displayName = null,
        [Description("Optional service description")] string? description = null,
        [Description("Startup type: Automatic | AutomaticDelayedStart | Manual | Disabled. Default Manual.")] string? startupType = null,
        [Description("Optional comma-separated list of service short-names this service depends on")] string? dependencies = null)
    {
        admin.EnsureOperationAllowed(Operation.WinCreateService);
        var target = inventory.GetRequired(server);
        const string script = """
            param($name, $binaryPath, $displayName, $description, $startupType, $dependencies)
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
                throw "Service '$name' already exists. Use win_delete_service first if you want to recreate it."
            }
            $params = @{
                Name           = $name
                BinaryPathName = $binaryPath
                ErrorAction    = 'Stop'
            }
            if ($displayName)  { $params['DisplayName']  = $displayName }
            if ($description)  { $params['Description']  = $description }
            if ($startupType)  { $params['StartupType']  = $startupType }
            if ($dependencies) {
                $params['DependsOn'] = ($dependencies -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }
            $svc = New-Service @params
            [PSCustomObject]@{
                Name         = $svc.Name
                DisplayName  = $svc.DisplayName
                StartType    = $svc.StartType.ToString()
                Status       = $svc.Status.ToString()
                BinaryPath   = $binaryPath
                Description  = $description
            }
            """;
        return exec.InvokeRemoteJson(target, script,
            new object?[] { serviceName, binaryPath, displayName, description, startupType, dependencies },
            jsonDepth: 3);
    }

    [McpServerTool(Name = "win_delete_service"),
     Description("Delete a Windows service on a remote machine via the WMI Win32_Service.Delete method. Refuses if the service is running unless force=true (in which case it's stopped first). Blocked by RemoteAdmin:Operations:WinDeleteService.")]
    public static string DeleteService(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Service short name (Win32_Service.Name, not DisplayName)")] string serviceName,
        [Description("If true and the service is running, stop it before deleting. Default false.")] bool force = false)
    {
        admin.EnsureOperationAllowed(Operation.WinDeleteService);
        var target = inventory.GetRequired(server);
        // WQL string-escape: doubling single quotes neutralises the only special char inside a
        // quoted WQL literal. The script param-binding avoids any further shell exposure.
        const string script = """
            param($name, $force)
            $escaped = $name -replace "'","''"
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escaped'" -ErrorAction Stop
            if (-not $svc) { throw "Service not found: $name" }
            $wasRunning = ($svc.State -eq 'Running')
            if ($wasRunning) {
                if (-not $force) {
                    throw "Service '$name' is running. Pass force=true to stop it before deletion."
                }
                Stop-Service -Name $name -Force -ErrorAction Stop
            }
            $result = $svc | Invoke-CimMethod -MethodName Delete
            if ($result.ReturnValue -ne 0) {
                # WMI Win32_Service.Delete return codes — surface the well-known ones.
                $msg = switch ($result.ReturnValue) {
                    1  { 'Not Supported' }
                    2  { 'Access Denied' }
                    3  { 'Dependent Services Running' }
                    4  { 'Invalid Service Control' }
                    5  { 'Service Cannot Accept Control' }
                    6  { 'Service Not Active' }
                    7  { 'Service Request Timeout' }
                    8  { 'Unknown Failure' }
                    9  { 'Path Not Found' }
                    10 { 'Service Already Running' }
                    11 { 'Service Database Locked' }
                    12 { 'Service Dependency Deleted' }
                    13 { 'Service Dependency Failure' }
                    14 { 'Service Disabled' }
                    15 { 'Service Logon Failure' }
                    16 { 'Service Marked For Deletion (will be removed when no handles remain)' }
                    17 { 'Service No Thread' }
                    21 { 'Invalid Parameter' }
                    22 { 'User Account Not Found' }
                    23 { 'Service Exists' }
                    24 { 'Service Already Paused' }
                    default { 'Unknown' }
                }
                throw "WMI Delete returned code $($result.ReturnValue): $msg"
            }
            [PSCustomObject]@{
                Name          = $name
                Deleted       = $true
                StoppedFirst  = $wasRunning
                ReturnValue   = $result.ReturnValue
            }
            """;
        return exec.InvokeRemoteJson(target, script,
            new object?[] { serviceName, force }, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_kill_process"),
     Description("Terminate a process by id on a remote Windows machine. Blocked by RemoteAdmin:ReadOnly.")]
    public static string KillProcess(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Target ProcessId")] int processId)
    {
        admin.EnsureOperationAllowed(Operation.WinKillProcess);
        var target = inventory.GetRequired(server);
        const string script = """
            param($id)
            Stop-Process -Id $id -Force -ErrorAction Stop
            [PSCustomObject]@{ ProcessId = $id; Action = 'Stopped' }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { processId });
    }

    private static string RunServiceCommand(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        string server,
        string serviceName,
        string cmdletInvocation)
    {
        var target = inventory.GetRequired(server);
        // -PassThru returns the resulting ServiceController; we then ToString it for the JSON shape.
        var script = $$"""
            param($name)
            {{cmdletInvocation}} -Name $name -PassThru -ErrorAction Stop |
                Select-Object Name, DisplayName, Status, StartType
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { serviceName });
    }
}
