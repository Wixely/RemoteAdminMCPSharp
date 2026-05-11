using System.Text.Json.Serialization;

namespace RemoteAdminMCPSharp.Configuration;

/// <summary>
/// Root of the master credentials/inventory file. The hierarchy mirrors how RDCMan organises
/// servers: a tree of groups, each containing more groups and/or servers, with credentials
/// inheritable from a parent (resolved at load time).
/// </summary>
public sealed class ServerInventory
{
    /// <summary>Inventory schema version. Bump when the structure changes incompatibly.</summary>
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    /// <summary>Optional default credentials applied to any group/server without its own credentials.</summary>
    [JsonPropertyName("defaultCredentials")]
    public ServerCredentials? DefaultCredentials { get; set; }

    [JsonPropertyName("groups")]
    public List<ServerGroup> Groups { get; set; } = new();

    /// <summary>Servers not nested inside a group.</summary>
    [JsonPropertyName("servers")]
    public List<ServerEntry> Servers { get; set; } = new();
}

public sealed class ServerGroup
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    /// <summary>Optional group-level credentials. Inherited by child groups/servers when they don't override.</summary>
    [JsonPropertyName("credentials")]
    public ServerCredentials? Credentials { get; set; }

    [JsonPropertyName("groups")]
    public List<ServerGroup> Groups { get; set; } = new();

    [JsonPropertyName("servers")]
    public List<ServerEntry> Servers { get; set; } = new();
}

public sealed class ServerEntry
{
    /// <summary>Display name (must be unique across the inventory).</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>DNS hostname or IP used for remote calls.</summary>
    [JsonPropertyName("host")]
    public string Host { get; set; } = string.Empty;

    /// <summary>
    /// "windows" or "linux". When null/empty, the inventory file's default OS is used
    /// (windows_servers.json → windows, linux_servers.json → linux).
    /// </summary>
    [JsonPropertyName("os")]
    public string? Os { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();

    /// <summary>Per-server credential override. Falls back to the parent group / default.</summary>
    [JsonPropertyName("credentials")]
    public ServerCredentials? Credentials { get; set; }
}

/// <summary>
/// Plain-text credential container. Note: stored in plaintext on disk for now — replace with a
/// secret store before production use.
/// </summary>
public sealed class ServerCredentials
{
    // ---- Windows-only ----

    /// <summary>AD/NT domain. Windows-only.</summary>
    [JsonPropertyName("domain")]
    public string? Domain { get; set; }

    /// <summary>Account name (Windows: <c>user</c>; Linux: SSH user).</summary>
    [JsonPropertyName("username")]
    public string? Username { get; set; }

    /// <summary>
    /// Plaintext password. Operator-friendly entry point — at next service start, this value is
    /// encrypted into <see cref="PasswordProtected"/> and this field is cleared on disk. Set
    /// (or re-set) this field whenever you want to update the password.
    /// </summary>
    [JsonPropertyName("password")]
    public string? Password { get; set; }

    /// <summary>
    /// Base64 ciphertext produced by the active credential protector. Written by the service —
    /// don't hand-edit. Read precedence: <see cref="Password"/> (if set) wins.
    /// </summary>
    [JsonPropertyName("passwordProtected")]
    public string? PasswordProtected { get; set; }

    // ---- Linux / SSH ----

    /// <summary>SSH port. Default 22.</summary>
    [JsonPropertyName("port")]
    public int? Port { get; set; }

    /// <summary>Absolute path to an SSH private key file. Preferred over Password when set.</summary>
    [JsonPropertyName("privateKeyPath")]
    public string? PrivateKeyPath { get; set; }

    /// <summary>
    /// Plaintext passphrase for the private key. Same auto-protect lifecycle as
    /// <see cref="Password"/>.
    /// </summary>
    [JsonPropertyName("privateKeyPassphrase")]
    public string? PrivateKeyPassphrase { get; set; }

    /// <summary>Base64 ciphertext of the private key passphrase.</summary>
    [JsonPropertyName("privateKeyPassphraseProtected")]
    public string? PrivateKeyPassphraseProtected { get; set; }

    /// <summary>
    /// Scheme name attached to the protected fields above, so future restarts can pick the
    /// matching protector to decrypt them. Examples: <c>dpapi-user</c>, <c>aesgcm-keyfile</c>.
    /// </summary>
    [JsonPropertyName("protectionScheme")]
    public string? ProtectionScheme { get; set; }

    /// <summary>
    /// If true, mutating Linux commands (systemctl start/stop/restart, kill) are prefixed with
    /// <c>sudo -n</c>. Configure passwordless sudo for the SSH user beforehand.
    /// </summary>
    [JsonPropertyName("useSudo")]
    public bool UseSudo { get; set; } = false;
}

/// <summary>
/// Flattened, fully-resolved view of a server (credentials inherited, group path attached).
/// Built once at startup by <c>ServerInventoryService</c>.
/// </summary>
public sealed class ResolvedServer
{
    public required string Name { get; init; }
    public required string Host { get; init; }
    public required string Os { get; init; }
    public string? Description { get; init; }
    public List<string> Tags { get; init; } = new();
    public List<string> GroupPath { get; init; } = new();
    public ServerCredentials? Credentials { get; init; }
}
