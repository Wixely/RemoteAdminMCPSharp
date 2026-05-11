using System.ComponentModel;
using System.Runtime.Versioning;
using ModelContextProtocol.Server;
using RemoteAdminMCPSharp.Services;

namespace RemoteAdminMCPSharp.Tools;

/// <summary>
/// Read-only Windows diagnostics, executed remotely over PowerShell Remoting (WinRM). Never
/// gated by ReadOnly — these tools cannot mutate the target.
/// </summary>
[SupportedOSPlatform("windows")]
[McpServerToolType]
public static class WindowsDiagnosticsTools
{
    [McpServerTool(Name = "win_list_services"),
     Description("List Windows services on a remote machine. Optional substring/state filters are applied server-side via Where-Object.")]
    public static string ListServices(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Optional case-insensitive substring filter on name or display name")] string? nameContains = null,
        [Description("Optional state filter, e.g. 'Running' or 'Stopped'")] string? state = null)
    {
        var target = inventory.GetRequired(server);
        const string script = """
            param($nameContains, $state)
            Get-CimInstance -ClassName Win32_Service |
                Where-Object {
                    (-not $nameContains -or $_.Name -like "*$nameContains*" -or $_.DisplayName -like "*$nameContains*") -and
                    (-not $state         -or $_.State -eq $state)
                } |
                Select-Object Name, DisplayName, State, StartMode, Status, ProcessId, StartName |
                Sort-Object DisplayName
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { nameContains, state });
    }

    [McpServerTool(Name = "win_service_details"),
     Description("Get full configuration for a single Windows service — basic info plus recovery actions (the Services.msc \"Recovery\" tab: first/second/subsequent failure action, reset period, restart delay, run-program command, reboot message), dependencies, dependents, and delayed-autostart flag. Locale-independent: reads the registry FailureActions binary blob directly rather than parsing sc.exe text output. Single service only — don't loop this over an inventory; use win_list_services for that.")]
    public static string ServiceDetails(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Service short name (Win32_Service.Name, not DisplayName)")] string serviceName)
    {
        var target = inventory.GetRequired(server);
        // FailureActions registry blob layout (REG_BINARY):
        //   [0..3]    DWORD  dwResetPeriod (seconds)
        //   [4..7]    DWORD  lpRebootMsg pointer (zero on disk — string in a sibling value)
        //   [8..11]   DWORD  lpCommand pointer    (zero on disk — string in a sibling value)
        //   [12..15]  DWORD  cActions
        //   [16..]    SC_ACTION[]: each is { DWORD Type; DWORD Delay (ms) }
        // RebootMessage / FailureCommand / FailureActionsOnNonCrashFailures live in sibling
        // registry values, not inside the blob.
        const string script = """
            param($name)
            $escaped = $name -replace "'","''"
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escaped'" -ErrorAction Stop
            if (-not $svc) { throw "Service not found: $name" }

            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"

            $resetPeriod = 0
            $actions = @()
            $fa = (Get-ItemProperty -Path $regPath -Name 'FailureActions' -ErrorAction SilentlyContinue).FailureActions
            if ($fa -and $fa.Length -ge 16) {
                $resetPeriod = [System.BitConverter]::ToUInt32($fa, 0)
                $cActions    = [System.BitConverter]::ToUInt32($fa, 12)
                $list = New-Object System.Collections.Generic.List[object]
                for ($i = 0; $i -lt $cActions; $i++) {
                    $offset = 16 + ($i * 8)
                    if (($offset + 8) -gt $fa.Length) { break }
                    $type  = [System.BitConverter]::ToUInt32($fa, $offset)
                    $delay = [System.BitConverter]::ToUInt32($fa, $offset + 4)
                    $typeName = switch ($type) {
                        0 { 'NONE' }
                        1 { 'RESTART' }
                        2 { 'REBOOT' }
                        3 { 'RUN_COMMAND' }
                        default { "UNKNOWN($type)" }
                    }
                    $list.Add([PSCustomObject]@{
                        Action  = $typeName
                        DelayMs = [int64]$delay
                    })
                }
                $actions = $list.ToArray()
            }

            $rebootMsg  = (Get-ItemProperty -Path $regPath -Name 'RebootMessage'  -ErrorAction SilentlyContinue).RebootMessage
            $failCmd    = (Get-ItemProperty -Path $regPath -Name 'FailureCommand' -ErrorAction SilentlyContinue).FailureCommand
            $flagOnNon  = (Get-ItemProperty -Path $regPath -Name 'FailureActionsOnNonCrashFailures' -ErrorAction SilentlyContinue).FailureActionsOnNonCrashFailures
            $delayed    = (Get-ItemProperty -Path $regPath -Name 'DelayedAutostart' -ErrorAction SilentlyContinue).DelayedAutostart

            # Dependencies & dependents via the ServiceController, which already resolves them.
            $sc = Get-Service -Name $name -ErrorAction Stop
            $dependsOn  = @($sc.ServicesDependedOn | ForEach-Object { $_.Name })
            $dependents = @($sc.DependentServices  | ForEach-Object { $_.Name })

            [PSCustomObject]@{
                Name             = $svc.Name
                DisplayName      = $svc.DisplayName
                Description      = $svc.Description
                State            = $svc.State
                StartMode        = $svc.StartMode
                Status           = $svc.Status
                ProcessId        = $svc.ProcessId
                StartName        = $svc.StartName
                PathName         = $svc.PathName
                ServiceType      = $svc.ServiceType
                AcceptStop       = [bool]$svc.AcceptStop
                AcceptPause      = [bool]$svc.AcceptPause
                DelayedAutoStart = ($delayed -eq 1)
                DependsOn        = $dependsOn
                Dependents       = $dependents
                Recovery = [PSCustomObject]@{
                    ResetPeriodSeconds      = [int64]$resetPeriod
                    Actions                 = $actions
                    RebootMessage           = $rebootMsg
                    RunProgramCommand       = $failCmd
                    EnableForNonCrashStops  = ($flagOnNon -eq 1)
                }
            }
            """;
        return exec.InvokeRemoteJson(target, script, new object?[] { serviceName }, jsonDepth: 5);
    }

    [McpServerTool(Name = "win_list_processes"),
     Description("List running processes on a remote Windows machine with full health stats per process: PID, name, command line, executable path, CPU% (raw and normalised to total-system 0-100), working set, private working set, thread count, handle count, and creation date. Joins Win32_Process with Win32_PerfFormattedData_PerfProc_Process so a single call gets you everything an agent needs to judge process health without falling back to win_run_command.")]
    public static string ListProcesses(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Optional case-insensitive substring filter on process name")] string? nameContains = null,
        [Description("Max rows (default 200)")] int top = 200,
        [Description("Sort field: memory (default, working set desc), cpu (CPU% desc), private (private working set desc), name (asc), pid (asc).")] string? sortBy = null)
    {
        var target = inventory.GetRequired(server);
        const string script = """
            param($nameContains, $top, $sortBy)

            # Total cores so we can normalise CPU% to a 0–100 "of total system" value.
            $cores = (Get-CimInstance -ClassName Win32_ComputerSystem -Property NumberOfLogicalProcessors).NumberOfLogicalProcessors

            # PID-keyed lookup of perf counter data. Win32_PerfFormattedData_PerfProc_Process is one
            # of the slower CIM classes (enumerates every process) but does the rate computation
            # server-side, so we get instant CPU% without sampling locally.
            $perfByPid = @{}
            Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process |
                Where-Object { $_.IDProcess -gt 0 } |
                ForEach-Object { $perfByPid[[int]$_.IDProcess] = $_ }

            $rows = Get-CimInstance -ClassName Win32_Process |
                Where-Object { -not $nameContains -or $_.Name -like "*$nameContains*" } |
                ForEach-Object {
                    $proc = $_
                    $perf = $perfByPid[[int]$proc.ProcessId]
                    $cpu = if ($perf) { [double]$perf.PercentProcessorTime } else { 0 }
                    [PSCustomObject]@{
                        ProcessId              = [int]$proc.ProcessId
                        Name                   = $proc.Name
                        CommandLine            = $proc.CommandLine
                        ExecutablePath         = $proc.ExecutablePath
                        # Raw CPU% — can exceed 100 on multi-core (sum across all logical CPUs).
                        CpuPercent             = $cpu
                        # CPU% expressed as fraction of total system capacity (0..100).
                        CpuPercentOfTotal      = if ($cores -gt 0) { [math]::Round($cpu / $cores, 2) } else { 0 }
                        WorkingSetBytes        = [int64]$proc.WorkingSetSize
                        # Private bytes = memory not shared with other processes (closer to what
                        # Task Manager's "Memory" column shows).
                        PrivateWorkingSetBytes = if ($perf) { [int64]$perf.WorkingSetPrivate } else { $null }
                        ThreadCount            = if ($perf) { [int]$perf.ThreadCount } else { $null }
                        HandleCount            = if ($perf) { [int]$perf.HandleCount } else { $null }
                        CreationDate           = $proc.CreationDate
                    }
                }

            $sorted = switch ($sortBy) {
                'cpu'     { $rows | Sort-Object -Property CpuPercent             -Descending }
                'memory'  { $rows | Sort-Object -Property WorkingSetBytes        -Descending }
                'private' { $rows | Sort-Object -Property PrivateWorkingSetBytes -Descending }
                'name'    { $rows | Sort-Object -Property Name }
                'pid'     { $rows | Sort-Object -Property ProcessId }
                default   { $rows | Sort-Object -Property WorkingSetBytes        -Descending }
            }

            $sorted | Select-Object -First $top
            """;
        return exec.InvokeRemoteJson(target, script,
            new object?[] { nameContains, Math.Max(1, top), sortBy }, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_list_storage"),
     Description("List local fixed disks on a remote Windows machine with size / free / percent-free. By default, removable, CD-ROM, and network drives are filtered out at the WMI provider — a disconnected SAN LUN or dead network drive can otherwise hang WMI for the full operation timeout.")]
    public static string ListStorage(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server,
        [Description("Include removable, CD-ROM, and network drives (DriveType != 3). Off by default to avoid hangs on disconnected SAN/network volumes.")] bool includeRemovableAndNetwork = false)
    {
        var target = inventory.GetRequired(server);
        // DriveType 3 = Local Fixed Disk. Filtering at the WMI layer lets the provider short-circuit
        // before it tries to enumerate (and potentially block on) sick removable / remote volumes.
        var filter = includeRemovableAndNetwork ? "" : " -Filter \"DriveType=3\"";
        var script = $$$"""
            Get-CimInstance -ClassName Win32_LogicalDisk{{{filter}}} |
                Select-Object DeviceID, DriveType, FileSystem, VolumeName,
                              @{Name='SizeBytes'; Expression={[int64]$_.Size}},
                              @{Name='FreeBytes'; Expression={[int64]$_.FreeSpace}},
                              @{Name='UsedBytes'; Expression={[int64]($_.Size - $_.FreeSpace)}},
                              @{Name='PercentFree'; Expression={
                                  if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 2) } else { 0 }
                              }}
            """;
        return exec.InvokeRemoteJson(target, script);
    }

    [McpServerTool(Name = "win_cpu_usage"),
     Description("Sample current CPU load on a remote Windows machine. Returns per-core entries plus _Total.")]
    public static string CpuUsage(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        const string script = """
            Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor |
                Select-Object @{Name='Core'; Expression={$_.Name}},
                              @{Name='PercentBusy'; Expression={[int64]$_.PercentProcessorTime}}
            """;
        return exec.InvokeRemoteJson(target, script);
    }

    [McpServerTool(Name = "win_ram_usage"),
     Description("Get total / free physical and virtual memory on a remote Windows machine.")]
    public static string RamUsage(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        // Win32_OperatingSystem reports memory in KB — convert to bytes here so callers don't have to.
        const string script = """
            Get-CimInstance -ClassName Win32_OperatingSystem |
                Select-Object @{Name='OsCaption'; Expression={$_.Caption}},
                              @{Name='OsVersion'; Expression={$_.Version}},
                              @{Name='TotalPhysicalBytes';  Expression={[int64]$_.TotalVisibleMemorySize * 1024}},
                              @{Name='FreePhysicalBytes';   Expression={[int64]$_.FreePhysicalMemory     * 1024}},
                              @{Name='UsedPhysicalBytes';   Expression={[int64]($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) * 1024}},
                              @{Name='PercentPhysicalFree'; Expression={
                                  if ($_.TotalVisibleMemorySize -gt 0) {
                                      [math]::Round(($_.FreePhysicalMemory / $_.TotalVisibleMemorySize) * 100, 2)
                                  } else { 0 }
                              }},
                              @{Name='TotalVirtualBytes';   Expression={[int64]$_.TotalVirtualMemorySize * 1024}},
                              @{Name='FreeVirtualBytes';    Expression={[int64]$_.FreeVirtualMemory      * 1024}}
            """;
        return exec.InvokeRemoteJson(target, script);
    }

    [McpServerTool(Name = "win_list_active_users"),
     Description("List users with active or disconnected interactive sessions on a remote Windows machine (console + RDP). Uses quser.exe — present on every Windows since 2000.")]
    public static string ListActiveUsers(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        // quser exits non-zero with no output when there are no sessions; suppress stderr.
        // First column is '>' for current user / space otherwise; SessionName column is blank for
        // disconnected sessions so the regex makes that group optional.
        const string script = """
            $raw = $null
            try { $raw = & quser.exe 2>$null } catch { }
            if (-not $raw) { return @() }

            $rows = foreach ($line in ($raw | Select-Object -Skip 1)) {
                if ($line -match '^[ >](\S+)\s+(?:(\S+)\s+)?(\d+)\s+(\S+)\s+(\S+)\s+(.+)$') {
                    [PSCustomObject]@{
                        User        = $Matches[1]
                        SessionName = if ($Matches[2]) { $Matches[2] } else { $null }
                        SessionId   = [int]$Matches[3]
                        State       = $Matches[4]
                        IdleTime    = $Matches[5]
                        LogonTime   = $Matches[6].Trim()
                    }
                }
            }
            $rows
            """;
        return exec.InvokeRemoteJson(target, script, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_os_version"),
     Description("Get the most granular Windows OS version available — full Major.Minor.Build.UBR (e.g. 10.0.17763.5458), DisplayVersion (22H2-style feature update), EditionID, InstallationType (Server / Server Core / Client), and the BuildLabEx string. Reads two registry keys directly — much cheaper than a Win32_OperatingSystem WMI roundtrip.")]
    public static string OsVersion(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        // CurrentMajorVersionNumber/CurrentMinorVersionNumber are Win10/Server2016+; fall back to
        // the legacy CurrentVersion string for older boxes so this works everywhere.
        const string script = """
            $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name 'PROCESSOR_ARCHITECTURE' -ErrorAction SilentlyContinue

            $majorMinor = if ($cv.CurrentMajorVersionNumber) {
                "$($cv.CurrentMajorVersionNumber).$($cv.CurrentMinorVersionNumber)"
            } else { $cv.CurrentVersion }
            $build = $cv.CurrentBuildNumber
            $ubr   = $cv.UBR
            $full  = if ($ubr) { "$majorMinor.$build.$ubr" } else { "$majorMinor.$build" }

            [PSCustomObject]@{
                ProductName      = $cv.ProductName
                DisplayVersion   = $cv.DisplayVersion
                ReleaseId        = $cv.ReleaseId
                EditionId        = $cv.EditionID
                InstallationType = $cv.InstallationType
                BuildNumber      = $build
                Ubr              = $ubr
                FullVersion      = $full
                BuildLab         = $cv.BuildLab
                BuildLabEx       = $cv.BuildLabEx
                Architecture     = $sm.PROCESSOR_ARCHITECTURE
            }
            """;
        return exec.InvokeRemoteJson(target, script, jsonDepth: 3);
    }

    [McpServerTool(Name = "win_system_info"),
     Description("Get high-level OS / hardware info from a remote Windows machine.")]
    public static string SystemInfo(
        ServerInventoryService inventory,
        PowerShellRemoteExecutor exec,
        [Description("Server name as it appears in the inventory")] string server)
    {
        var target = inventory.GetRequired(server);
        const string script = """
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem
            [PSCustomObject]@{
                Os = [PSCustomObject]@{
                    Caption        = $os.Caption
                    Version        = $os.Version
                    BuildNumber    = $os.BuildNumber
                    Architecture   = $os.OSArchitecture
                    LastBootUpTime = $os.LastBootUpTime
                    InstallDate    = $os.InstallDate
                }
                Computer = [PSCustomObject]@{
                    Name                   = $cs.Name
                    Domain                 = $cs.Domain
                    Manufacturer           = $cs.Manufacturer
                    Model                  = $cs.Model
                    LogicalProcessors      = [int]$cs.NumberOfLogicalProcessors
                    TotalPhysicalMemoryBytes = [int64]$cs.TotalPhysicalMemory
                }
            }
            """;
        return exec.InvokeRemoteJson(target, script, jsonDepth: 5);
    }
}
