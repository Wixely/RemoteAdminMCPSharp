using System.ComponentModel;
using System.Runtime.Versioning;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Configuration;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// IIS administration tools — sites, app pools, bindings, iisreset. Uses the WebAdministration
/// PowerShell module, which ships with the IIS Management Scripts and Tools feature on any
/// Windows Server running IIS. Reads are unrestricted; writes are gated per-operation.
/// </summary>
[SupportedOSPlatform("windows")]
[McpServerToolType]
public static class WindowsIisTools
{
    // ---- Read-only ----

    [McpServerTool(Name = "win_iis_list_sites"),
     Description("List IIS sites on a remote Windows host with state, physical path, application pool, enabled protocols, and full binding info — including for HTTPS bindings the certificate thumbprint, store, subject, issuer, and NotBefore/NotAfter UTC. Requires the WebAdministration PowerShell module (standard with IIS).")]
    public static string ListSites(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Optional case-insensitive substring filter on site name")] string? nameContains = null)
    {
        var target = inventory.GetRequired(server);
        const string script = """
            param($nameContains)
            Import-Module WebAdministration -ErrorAction Stop

            $sites = Get-Website
            if ($nameContains) {
                $sites = $sites | Where-Object { $_.name -like "*$nameContains*" }
            }

            foreach ($site in $sites) {
                $bindings = @()
                foreach ($b in (Get-WebBinding -Name $site.Name)) {
                    $parts = $b.bindingInformation -split ':', 3
                    $cert = $null
                    if ($b.protocol -eq 'https' -and $b.certificateHash) {
                        $thumb = ($b.certificateHash | ForEach-Object { '{0:X2}' -f $_ }) -join ''
                        $store = if ($b.certificateStoreName) { $b.certificateStoreName } else { 'My' }
                        $certObj = Get-ChildItem -Path "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
                                       Where-Object { $_.Thumbprint -eq $thumb }
                        $cert = [PSCustomObject]@{
                            Thumbprint   = $thumb
                            StoreName    = $store
                            Subject      = if ($certObj) { $certObj.Subject }      else { $null }
                            Issuer       = if ($certObj) { $certObj.Issuer }       else { $null }
                            NotBeforeUtc = if ($certObj) { $certObj.NotBefore.ToUniversalTime().ToString('o') } else { $null }
                            NotAfterUtc  = if ($certObj) { $certObj.NotAfter.ToUniversalTime().ToString('o') }  else { $null }
                            IsExpired    = if ($certObj) { $certObj.NotAfter -lt (Get-Date) } else { $null }
                        }
                    }
                    $bindings += [PSCustomObject]@{
                        Protocol    = $b.protocol
                        IpAddress   = $parts[0]
                        Port        = [int]$parts[1]
                        HostHeader  = $parts[2]
                        SniEnabled  = (([int]$b.sslFlags) -band 1) -eq 1
                        Certificate = $cert
                    }
                }
                [PSCustomObject]@{
                    Id               = [int64]$site.id
                    Name             = $site.name
                    State            = $site.state
                    PhysicalPath     = $site.physicalPath
                    ApplicationPool  = $site.applicationPool
                    EnabledProtocols = $site.enabledProtocols
                    Bindings         = $bindings
                }
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { nameContains }, jsonDepth: 6);
    }

    [McpServerTool(Name = "win_iis_list_app_pools"),
     Description("List IIS application pools on a remote Windows host with state, .NET runtime version, pipeline mode, identity, idle timeout, and start mode. Requires the WebAdministration PowerShell module.")]
    public static string ListAppPools(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Optional case-insensitive substring filter on app-pool name")] string? nameContains = null)
    {
        var target = inventory.GetRequired(server);
        const string script = """
            param($nameContains)
            Import-Module WebAdministration -ErrorAction Stop

            $pools = Get-ChildItem 'IIS:\AppPools'
            if ($nameContains) {
                $pools = $pools | Where-Object { $_.Name -like "*$nameContains*" }
            }

            foreach ($pool in $pools) {
                $stateInfo = Get-WebAppPoolState -Name $pool.Name
                [PSCustomObject]@{
                    Name                  = $pool.Name
                    State                 = $stateInfo.Value
                    AutoStart             = [bool]$pool.autoStart
                    ManagedRuntimeVersion = $pool.managedRuntimeVersion
                    ManagedPipelineMode   = $pool.managedPipelineMode
                    Enable32BitOnWin64    = [bool]$pool.enable32BitAppOnWin64
                    IdentityType          = $pool.processModel.identityType
                    UserName              = $pool.processModel.userName
                    IdleTimeoutMinutes    = $pool.processModel.idleTimeout.TotalMinutes
                    StartMode             = $pool.startMode
                    QueueLength           = $pool.queueLength
                    RecyclingPeriodMinutes = $pool.recycling.periodicRestart.time.TotalMinutes
                }
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { nameContains }, jsonDepth: 4);
    }

    // ---- Mutating ----

    [McpServerTool(Name = "win_iis_start_site"),
     Description("Start an IIS site on a remote Windows host. Blocked by RemoteAdmin:Operations:WinIisStartSite.")]
    public static string StartSite(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("IIS site name (the 'name' column from win_iis_list_sites)")] string siteName)
    {
        admin.EnsureOperationAllowed(Operation.WinIisStartSite);
        return RunSiteAction(inventory, exec, server, siteName, "Start-Website");
    }

    [McpServerTool(Name = "win_iis_stop_site"),
     Description("Stop an IIS site on a remote Windows host. Blocked by RemoteAdmin:Operations:WinIisStopSite.")]
    public static string StopSite(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("IIS site name")] string siteName)
    {
        admin.EnsureOperationAllowed(Operation.WinIisStopSite);
        return RunSiteAction(inventory, exec, server, siteName, "Stop-Website");
    }

    [McpServerTool(Name = "win_iis_delete_site"),
     Description("Remove an IIS site definition from IIS without deleting its physical files. Blocked by RemoteAdmin:Operations:WinIisDeleteSite.")]
    public static string DeleteSite(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("IIS site name")] string siteName)
    {
        admin.EnsureOperationAllowed(Operation.WinIisDeleteSite);
        var target = inventory.GetRequired(server);
        const string script = """
            param($name)
            Import-Module WebAdministration -ErrorAction Stop

            $site = Get-Website -Name $name -ErrorAction SilentlyContinue
            if (-not $site) {
                throw "IIS site not found: $name"
            }

            $bindings = @(
                Get-WebBinding -Name $name |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Protocol           = $_.protocol
                            BindingInformation = $_.bindingInformation
                        }
                    }
            )

            $physicalPath = $site.physicalPath
            $applicationPool = $site.applicationPool
            Remove-Website -Name $name -ErrorAction Stop

            [PSCustomObject]@{
                Name            = $name
                RemovedFromIis  = $true
                FilesDeleted    = $false
                PhysicalPath    = $physicalPath
                ApplicationPool = $applicationPool
                Bindings        = $bindings
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { siteName }, jsonDepth: 4);
    }

    [McpServerTool(Name = "win_iis_start_app_pool"),
     Description("Start an IIS application pool on a remote Windows host. Blocked by RemoteAdmin:Operations:WinIisStartAppPool.")]
    public static string StartAppPool(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("App-pool name")] string appPoolName)
    {
        admin.EnsureOperationAllowed(Operation.WinIisStartAppPool);
        return RunAppPoolAction(inventory, exec, server, appPoolName, "Start-WebAppPool");
    }

    [McpServerTool(Name = "win_iis_stop_app_pool"),
     Description("Stop an IIS application pool on a remote Windows host. Blocked by RemoteAdmin:Operations:WinIisStopAppPool.")]
    public static string StopAppPool(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("App-pool name")] string appPoolName)
    {
        admin.EnsureOperationAllowed(Operation.WinIisStopAppPool);
        return RunAppPoolAction(inventory, exec, server, appPoolName, "Stop-WebAppPool");
    }

    [McpServerTool(Name = "win_iis_recycle_app_pool"),
     Description("Recycle (graceful in-place restart) an IIS application pool on a remote Windows host — workers are drained, then a fresh worker process is spawned. Preferred over stop+start for live services. Blocked by RemoteAdmin:Operations:WinIisRecycleAppPool.")]
    public static string RecycleAppPool(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("App-pool name")] string appPoolName)
    {
        admin.EnsureOperationAllowed(Operation.WinIisRecycleAppPool);
        return RunAppPoolAction(inventory, exec, server, appPoolName, "Restart-WebAppPool");
    }

    [McpServerTool(Name = "win_iis_delete_app_pool"),
     Description("Remove an IIS application pool definition without deleting site or application files. Refuses to delete an app pool still used by sites or applications unless force=true. Blocked by RemoteAdmin:Operations:WinIisDeleteAppPool.")]
    public static string DeleteAppPool(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("IIS application pool name")] string appPoolName,
        [Description("If true, delete even when the app pool is still referenced by sites or applications. Default false.")] bool force = false)
    {
        admin.EnsureOperationAllowed(Operation.WinIisDeleteAppPool);
        var target = inventory.GetRequired(server);
        const string script = """
            param($name, $force)
            Import-Module WebAdministration -ErrorAction Stop

            $poolPath = "IIS:\AppPools\$name"
            $pool = Get-Item -LiteralPath $poolPath -ErrorAction SilentlyContinue
            if (-not $pool) {
                throw "IIS application pool not found: $name"
            }

            $references = @()
            foreach ($site in Get-Website) {
                if ($site.applicationPool -eq $name) {
                    $references += [PSCustomObject]@{
                        Type = 'Site'
                        Name = $site.name
                        Path = $site.name
                    }
                }

                foreach ($app in Get-WebApplication -Site $site.name) {
                    if ($app.applicationPool -eq $name) {
                        $references += [PSCustomObject]@{
                            Type = 'Application'
                            Name = $app.path
                            Path = "$($site.name)$($app.path)"
                        }
                    }
                }
            }

            if ($references.Count -gt 0 -and -not $force) {
                $names = ($references | ForEach-Object { "$($_.Type):$($_.Path)" }) -join ', '
                throw "IIS application pool '$name' is still referenced by: $names. Pass force=true to remove it anyway."
            }

            $state = Get-WebAppPoolState -Name $name -ErrorAction SilentlyContinue
            $managedRuntimeVersion = $pool.managedRuntimeVersion
            $managedPipelineMode = $pool.managedPipelineMode
            Remove-WebAppPool -Name $name -ErrorAction Stop

            [PSCustomObject]@{
                Name                  = $name
                RemovedFromIis        = $true
                FilesDeleted          = $false
                Forced                = [bool]$force
                PreviousState         = if ($state) { $state.Value } else { $null }
                ManagedRuntimeVersion = $managedRuntimeVersion
                ManagedPipelineMode   = $managedPipelineMode
                References            = $references
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { appPoolName, force }, jsonDepth: 5);
    }

    [McpServerTool(Name = "win_iis_reset"),
     Description("Run iisreset.exe on a remote Windows host — stops then starts ALL IIS services (W3SVC, WAS, etc.). Heavy hammer: takes ~10–30s and brings every site offline during the cycle. Use win_iis_recycle_app_pool for single-pool restarts when possible. Blocked by RemoteAdmin:Operations:WinIisReset.")]
    public static string IisReset(
        RemoteAdminService admin,
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Action: 'restart' (default), 'stop', or 'start'.")] string action = "restart")
    {
        admin.EnsureOperationAllowed(Operation.WinIisReset);
        var target = inventory.GetRequired(server);
        var flag = action?.Trim().ToLowerInvariant() switch
        {
            "stop" => "/stop",
            "start" => "/start",
            "restart" => "/restart",
            null or "" => "/restart",
            _ => throw new ArgumentException("action must be one of: restart, stop, start"),
        };
        const string script = """
            param($flag)
            $out = & iisreset.exe $flag 2>&1 | Out-String
            [PSCustomObject]@{
                Action   = $flag
                ExitCode = $LASTEXITCODE
                Output   = $out
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { flag }, jsonDepth: 3);
    }

    // ---- helpers ----

    private static string RunSiteAction(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        string server,
        string siteName,
        string cmdlet)
    {
        var target = inventory.GetRequired(server);
        var script = $$"""
            param($name)
            Import-Module WebAdministration -ErrorAction Stop
            {{cmdlet}} -Name $name -ErrorAction Stop
            $site = Get-Website -Name $name
            [PSCustomObject]@{
                Name  = $site.name
                State = $site.state
                Action = '{{cmdlet}}'
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { siteName }, jsonDepth: 3);
    }

    private static string RunAppPoolAction(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        string server,
        string appPoolName,
        string cmdlet)
    {
        var target = inventory.GetRequired(server);
        var script = $$"""
            param($name)
            Import-Module WebAdministration -ErrorAction Stop
            {{cmdlet}} -Name $name -ErrorAction Stop
            $state = Get-WebAppPoolState -Name $name
            [PSCustomObject]@{
                Name   = $name
                State  = $state.Value
                Action = '{{cmdlet}}'
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { appPoolName }, jsonDepth: 3);
    }
}
