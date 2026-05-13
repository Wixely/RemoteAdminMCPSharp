namespace RemoteAdminMCPSharp.Configuration;

/// <summary>
/// Every mutating tool the server exposes, named so it can be toggled individually under
/// <c>RemoteAdmin:Operations</c>. Read-only diagnostics aren't listed here — they never need
/// an opt-in switch.
/// </summary>
public enum Operation
{
    // ---- Windows: service / process management ----
    WinStartService,
    WinStopService,
    WinRestartService,
    WinCreateService,
    WinDeleteService,
    WinKillProcess,

    // ---- Windows: file management ----
    WinWriteFile,
    WinAppendToFile,
    WinCreateFolder,
    WinDeleteFile,
    WinDeleteFolder,
    WinCopyPath,
    WinMovePath,

    // ---- Windows: IIS ----
    WinIisStartSite,
    WinIisStopSite,
    WinIisStartAppPool,
    WinIisStopAppPool,
    WinIisRecycleAppPool,
    WinIisReset,

    // ---- Windows: arbitrary command ----
    WinRunCommand,

    // ---- Linux: service / process management ----
    LinuxStartService,
    LinuxStopService,
    LinuxRestartService,
    LinuxKillProcess,

    // ---- Linux: file management ----
    LinuxWriteFile,
    LinuxAppendToFile,
    LinuxCreateFolder,
    LinuxDeleteFile,
    LinuxDeleteFolder,
    LinuxCopyPath,
    LinuxMovePath,

    // ---- Linux: arbitrary command ----
    LinuxRunCommand,
}

/// <summary>
/// Per-operation allow-list. Every flag defaults to <c>false</c> — an operator must explicitly
/// enable each tool they want exposed, in addition to setting <c>RemoteAdmin:ReadOnly=false</c>.
///
/// This is layered defence on top of <c>ReadOnly</c>: flipping <c>ReadOnly</c> off does NOT
/// re-enable any of these — each tool still needs its own switch flipped.
/// </summary>
public sealed class OperationsOptions
{
    // Windows: service / process
    public bool WinStartService { get; set; } = false;
    public bool WinStopService { get; set; } = false;
    public bool WinRestartService { get; set; } = false;
    public bool WinCreateService { get; set; } = false;
    public bool WinDeleteService { get; set; } = false;
    public bool WinKillProcess { get; set; } = false;

    // Windows: files
    public bool WinWriteFile { get; set; } = false;
    public bool WinAppendToFile { get; set; } = false;
    public bool WinCreateFolder { get; set; } = false;
    public bool WinDeleteFile { get; set; } = false;
    public bool WinDeleteFolder { get; set; } = false;
    public bool WinCopyPath { get; set; } = false;
    public bool WinMovePath { get; set; } = false;

    // Windows: IIS
    public bool WinIisStartSite { get; set; } = false;
    public bool WinIisStopSite { get; set; } = false;
    public bool WinIisStartAppPool { get; set; } = false;
    public bool WinIisStopAppPool { get; set; } = false;
    public bool WinIisRecycleAppPool { get; set; } = false;
    public bool WinIisReset { get; set; } = false;

    // Windows: arbitrary
    public bool WinRunCommand { get; set; } = false;

    // Linux: service / process
    public bool LinuxStartService { get; set; } = false;
    public bool LinuxStopService { get; set; } = false;
    public bool LinuxRestartService { get; set; } = false;
    public bool LinuxKillProcess { get; set; } = false;

    // Linux: files
    public bool LinuxWriteFile { get; set; } = false;
    public bool LinuxAppendToFile { get; set; } = false;
    public bool LinuxCreateFolder { get; set; } = false;
    public bool LinuxDeleteFile { get; set; } = false;
    public bool LinuxDeleteFolder { get; set; } = false;
    public bool LinuxCopyPath { get; set; } = false;
    public bool LinuxMovePath { get; set; } = false;

    // Linux: arbitrary
    public bool LinuxRunCommand { get; set; } = false;

    public bool IsEnabled(Operation op) => op switch
    {
        Operation.WinStartService => WinStartService,
        Operation.WinStopService => WinStopService,
        Operation.WinRestartService => WinRestartService,
        Operation.WinCreateService => WinCreateService,
        Operation.WinDeleteService => WinDeleteService,
        Operation.WinKillProcess => WinKillProcess,
        Operation.WinWriteFile => WinWriteFile,
        Operation.WinAppendToFile => WinAppendToFile,
        Operation.WinCreateFolder => WinCreateFolder,
        Operation.WinDeleteFile => WinDeleteFile,
        Operation.WinDeleteFolder => WinDeleteFolder,
        Operation.WinCopyPath => WinCopyPath,
        Operation.WinMovePath => WinMovePath,
        Operation.WinIisStartSite => WinIisStartSite,
        Operation.WinIisStopSite => WinIisStopSite,
        Operation.WinIisStartAppPool => WinIisStartAppPool,
        Operation.WinIisStopAppPool => WinIisStopAppPool,
        Operation.WinIisRecycleAppPool => WinIisRecycleAppPool,
        Operation.WinIisReset => WinIisReset,
        Operation.WinRunCommand => WinRunCommand,
        Operation.LinuxStartService => LinuxStartService,
        Operation.LinuxStopService => LinuxStopService,
        Operation.LinuxRestartService => LinuxRestartService,
        Operation.LinuxKillProcess => LinuxKillProcess,
        Operation.LinuxWriteFile => LinuxWriteFile,
        Operation.LinuxAppendToFile => LinuxAppendToFile,
        Operation.LinuxCreateFolder => LinuxCreateFolder,
        Operation.LinuxDeleteFile => LinuxDeleteFile,
        Operation.LinuxDeleteFolder => LinuxDeleteFolder,
        Operation.LinuxCopyPath => LinuxCopyPath,
        Operation.LinuxMovePath => LinuxMovePath,
        Operation.LinuxRunCommand => LinuxRunCommand,
        _ => throw new ArgumentOutOfRangeException(nameof(op)),
    };
}
