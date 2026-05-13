namespace RemoteAdminMCPSharp.Configuration;

public sealed class RemoteAdminOptions
{
    public const string SectionName = "RemoteAdmin";

    /// <summary>
    /// When true, all non-diagnostic operations (start/stop/restart services, kill processes, etc.)
    /// are blocked. Default true.
    /// </summary>
    public bool ReadOnly { get; set; } = true;

    /// <summary>
    /// When true, the per-OS "arbitrary command" tool is exposed. Default false.
    /// </summary>
    public bool AllowArbitraryCommands { get; set; } = false;

    /// <summary>
    /// Default WinRM/WMI timeout in seconds for remote operations.
    /// </summary>
    public int RemoteOperationTimeoutSeconds { get; set; } = 60;

    /// <summary>
    /// Path to the Windows inventory/credentials file. Relative paths resolve from the executable
    /// directory.
    /// </summary>
    public string WindowsInventoryPath { get; set; } = "remote_admin_windows_servers.json";

    /// <summary>
    /// Path to the Linux inventory/credentials file. Relative paths resolve from the executable
    /// directory.
    /// </summary>
    public string LinuxInventoryPath { get; set; } = "remote_admin_linux_servers.json";

    /// <summary>
    /// Optional folder containing one or more .rdg (RDCMan) files. Servers found there are merged
    /// into the inventory at startup.
    /// </summary>
    public string? RdgImportPath { get; set; }

    /// <summary>
    /// Active credential-protection scheme. Values:
    /// <list type="bullet">
    ///   <item><c>auto</c> (default) — DPAPI-user on Windows, AES-GCM keyfile on Linux/macOS.</item>
    ///   <item><c>dpapi-user</c> — Windows only.</item>
    ///   <item><c>dpapi-machine</c> — Windows only.</item>
    ///   <item><c>aesgcm-keyfile</c> — cross-platform; uses <see cref="KeyFilePath"/>.</item>
    ///   <item><c>none</c> — disable; plaintext stays in the inventory files as-is.</item>
    /// </list>
    /// </summary>
    public string CredentialProtection { get; set; } = "auto";

    /// <summary>
    /// When true (default), at startup any plaintext <c>password</c> / <c>privateKeyPassphrase</c>
    /// fields in the inventory files are encrypted, written back atomically, and the plaintext
    /// fields cleared. Disable for read-only filesystems or air-gapped testing.
    /// </summary>
    public bool AutoProtectCredentials { get; set; } = true;

    /// <summary>
    /// Path to the AES-GCM master key file (used by the <c>aesgcm-keyfile</c> scheme). Defaults
    /// to <c>master.key</c> next to the executable. Created with 0600 perms on first boot.
    /// </summary>
    public string KeyFilePath { get; set; } = "master.key";

    /// <summary>
    /// If true, treat the configured arbitrary-command tool output as untrusted and truncate it.
    /// </summary>
    public int ArbitraryCommandOutputCharLimit { get; set; } = 32_000;

    /// <summary>
    /// Optional allow-list of server names (matches Inventory entries). Empty = no restriction.
    /// </summary>
    public List<string> AllowedServers { get; set; } = new();

    /// <summary>
    /// Optional deny-list of server names. Evaluated after AllowedServers.
    /// </summary>
    public List<string> BlockedServers { get; set; } = new();

    /// <summary>
    /// Concurrency and rate-limiting bounds. See <see cref="ConcurrencyOptions"/>.
    /// </summary>
    public ConcurrencyOptions Concurrency { get; set; } = new();

    /// <summary>
    /// Per-operation allow list. Every mutating tool has its own switch here, all defaulting to
    /// <c>false</c>. Layered on top of <see cref="ReadOnly"/>: even with ReadOnly=false, each
    /// tool stays disabled until its switch is explicitly enabled.
    /// </summary>
    public OperationsOptions Operations { get; set; } = new();
}

public sealed class ServerOptions
{
    public const string SectionName = "Server";

    public string Host { get; set; } = "localhost";
    public int Port { get; set; } = 5706;
    public string Path { get; set; } = "/mcp";

    /// <summary>Service name when running as a Windows Service.</summary>
    public string WindowsServiceName { get; set; } = "RemoteAdminMCPSharp";

    /// <summary>Optional MCP endpoint password. Blank disables MCP password auth.</summary>
    public string Password { get; set; } = string.Empty;
}
