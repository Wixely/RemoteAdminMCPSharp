using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using RemoteAdminMCPSharp.Configuration;

namespace RemoteAdminMCPSharp.Services;

/// <summary>
/// Loads the Windows and Linux inventory files and (optionally) merges any RDCMan .rdg files
/// found under <c>RemoteAdmin:RdgImportPath</c>. On load each file is run through the credential
/// protection pass: any plaintext <c>password</c> / <c>privateKeyPassphrase</c> field is
/// encrypted, written back atomically, and the plaintext cleared. The in-memory
/// <see cref="ResolvedServer"/> entries always carry decrypted credentials so the executors don't
/// have to care.
/// </summary>
public sealed class ServerInventoryService
{
    private readonly RemoteAdminOptions _options;
    private readonly string _contentRoot;
    private readonly ILogger<ServerInventoryService> _logger;
    private readonly CredentialProtectionService _protection;
    private readonly Dictionary<string, ResolvedServer> _servers =
        new(StringComparer.OrdinalIgnoreCase);

    public ServerInventoryService(
        IOptions<RemoteAdminOptions> options,
        IHostEnvironment environment,
        ILogger<ServerInventoryService> logger,
        CredentialProtectionService protection)
    {
        _options = options.Value;
        _contentRoot = environment.ContentRootPath;
        _logger = logger;
        _protection = protection;
        LoadAll();
    }

    public IReadOnlyCollection<ResolvedServer> Servers => _servers.Values;

    public ResolvedServer GetRequired(string name)
    {
        if (!_servers.TryGetValue(name, out var server))
            throw new McpException(
                $"Unknown server '{name}'. Call the `list_servers` MCP tool to see the inventory " +
                "configured in this MCP server's remote_admin_windows_servers.json / remote_admin_linux_servers.json files.");

        if (_options.AllowedServers.Count > 0 &&
            !_options.AllowedServers.Contains(server.Name, StringComparer.OrdinalIgnoreCase))
        {
            throw new McpException(
                $"Server '{name}' is blocked by MCP server configuration: it is not in the allow-list " +
                "(RemoteAdmin:AllowedServers in RemoteAdminMCPSharp.json). The operator restricts this MCP server " +
                "to a specific set of hosts.");
        }
        if (_options.BlockedServers.Contains(server.Name, StringComparer.OrdinalIgnoreCase))
        {
            throw new McpException(
                $"Server '{name}' is blocked by MCP server configuration: it is in the deny-list " +
                "(RemoteAdmin:BlockedServers in RemoteAdminMCPSharp.json).");
        }
        return server;
    }

    private void LoadAll()
    {
        LoadInventoryFile(ResolvePath(_contentRoot, _options.WindowsInventoryPath), defaultOs: "windows");
        LoadInventoryFile(ResolvePath(_contentRoot, _options.LinuxInventoryPath), defaultOs: "linux");

        if (!string.IsNullOrWhiteSpace(_options.RdgImportPath))
        {
            var rdgDir = ResolvePath(_contentRoot, _options.RdgImportPath);
            ImportRdg(rdgDir);
        }

        _logger.LogInformation(
            "Inventory ready: {Count} server(s) registered ({Windows} windows / {Linux} linux), protection={Scheme}",
            _servers.Count,
            _servers.Values.Count(s => s.Os == "windows"),
            _servers.Values.Count(s => s.Os == "linux"),
            _protection.ActiveScheme);
    }

    private static string ResolvePath(string contentRoot, string path)
        => Path.IsPathRooted(path) ? path : Path.Combine(contentRoot, path);

    private void LoadInventoryFile(string path, string defaultOs)
    {
        if (!File.Exists(path))
        {
            _logger.LogWarning("Inventory file not found at {Path} (defaultOs={Os}); skipping", path, defaultOs);
            return;
        }

        ServerInventory inventory;
        try
        {
            var json = File.ReadAllText(path);
            inventory = JsonSerializer.Deserialize<ServerInventory>(json, JsonOpts.Read)
                        ?? new ServerInventory();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse inventory file {Path}", path);
            return;
        }

        if (_options.AutoProtectCredentials && _protection.IsEnabled)
        {
            var rewroteCount = ProtectPlaintextSecrets(inventory);
            if (rewroteCount > 0)
            {
                WriteAtomic(path, inventory);
                _logger.LogInformation(
                    "Encrypted {Count} plaintext secret(s) in {Path} using scheme {Scheme} and rewrote the file",
                    rewroteCount, path, _protection.ActiveScheme);
            }
        }

        _logger.LogInformation("Loaded {Os} inventory from {Path}", defaultOs, path);
        FlattenGroup(
            groups: inventory.Groups,
            servers: inventory.Servers,
            parentCreds: inventory.DefaultCredentials,
            path: new List<string>(),
            defaultOs: defaultOs);
    }

    /// <summary>
    /// Walks every credential bag in the inventory tree and replaces plaintext passwords /
    /// passphrases with their protected equivalents. Mutates the tree in place. Returns the
    /// number of secrets that were converted.
    /// </summary>
    private int ProtectPlaintextSecrets(ServerInventory inv)
    {
        var count = 0;
        foreach (var creds in EnumerateAllCredentials(inv))
        {
            if (!string.IsNullOrEmpty(creds.Password))
            {
                creds.PasswordProtected = _protection.Protect(creds.Password);
                creds.Password = null;
                creds.ProtectionScheme = _protection.ActiveScheme;
                count++;
            }
            if (!string.IsNullOrEmpty(creds.PrivateKeyPassphrase))
            {
                creds.PrivateKeyPassphraseProtected = _protection.Protect(creds.PrivateKeyPassphrase);
                creds.PrivateKeyPassphrase = null;
                creds.ProtectionScheme = _protection.ActiveScheme;
                count++;
            }
        }
        return count;
    }

    private static IEnumerable<ServerCredentials> EnumerateAllCredentials(ServerInventory inv)
    {
        if (inv.DefaultCredentials is not null) yield return inv.DefaultCredentials;
        foreach (var s in inv.Servers)
            if (s.Credentials is not null) yield return s.Credentials;
        foreach (var g in inv.Groups)
            foreach (var c in EnumerateGroupCredentials(g))
                yield return c;
    }

    private static IEnumerable<ServerCredentials> EnumerateGroupCredentials(ServerGroup g)
    {
        if (g.Credentials is not null) yield return g.Credentials;
        foreach (var s in g.Servers)
            if (s.Credentials is not null) yield return s.Credentials;
        foreach (var child in g.Groups)
            foreach (var c in EnumerateGroupCredentials(child))
                yield return c;
    }

    /// <summary>
    /// Atomic write: serialize to <c>path + ".tmp"</c>, then <see cref="File.Move(string, string, bool)"/>
    /// with overwrite. On a crash mid-write the original file is untouched.
    /// </summary>
    private static void WriteAtomic(string path, ServerInventory inv)
    {
        var tmp = path + ".tmp";
        var json = JsonSerializer.Serialize(inv, JsonOpts.Write);
        File.WriteAllText(tmp, json);
        File.Move(tmp, path, overwrite: true);
    }

    private void FlattenGroup(
        List<ServerGroup> groups,
        List<ServerEntry> servers,
        ServerCredentials? parentCreds,
        List<string> path,
        string defaultOs)
    {
        foreach (var server in servers)
        {
            var resolved = new ResolvedServer
            {
                Name = server.Name,
                Host = string.IsNullOrWhiteSpace(server.Host) ? server.Name : server.Host,
                Os = string.IsNullOrWhiteSpace(server.Os) ? defaultOs : server.Os!.ToLowerInvariant(),
                Description = server.Description,
                Tags = server.Tags,
                GroupPath = new List<string>(path),
                Credentials = ResolveCredentials(server.Credentials ?? parentCreds, server.Name),
            };
            AddOrWarn(resolved);
        }

        foreach (var group in groups)
        {
            var nextPath = new List<string>(path) { group.Name };
            var nextCreds = group.Credentials ?? parentCreds;
            FlattenGroup(group.Groups, group.Servers, nextCreds, nextPath, defaultOs);
        }
    }

    /// <summary>
    /// Build the runtime credentials view: plaintext fields take precedence, then protected
    /// fields are decrypted with the scheme they record. Returns a fresh instance so the
    /// in-memory copy can hold decrypted values without leaking back to disk.
    /// </summary>
    private ServerCredentials? ResolveCredentials(ServerCredentials? source, string ownerName)
    {
        if (source is null) return null;

        var resolved = new ServerCredentials
        {
            Domain = source.Domain,
            Username = source.Username,
            Port = source.Port,
            PrivateKeyPath = source.PrivateKeyPath,
            UseSudo = source.UseSudo,
            Password = source.Password,
            PrivateKeyPassphrase = source.PrivateKeyPassphrase,
        };

        try
        {
            if (string.IsNullOrEmpty(resolved.Password) && !string.IsNullOrEmpty(source.PasswordProtected))
                resolved.Password = _protection.Unprotect(source.PasswordProtected, source.ProtectionScheme);

            if (string.IsNullOrEmpty(resolved.PrivateKeyPassphrase) && !string.IsNullOrEmpty(source.PrivateKeyPassphraseProtected))
                resolved.PrivateKeyPassphrase = _protection.Unprotect(source.PrivateKeyPassphraseProtected, source.ProtectionScheme);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Failed to decrypt protected credentials for '{Owner}' (scheme={Scheme}). " +
                "Re-enter the plaintext password and restart to re-encrypt.",
                ownerName, source.ProtectionScheme ?? "(none)");
        }

        return resolved;
    }

    private void AddOrWarn(ResolvedServer server)
    {
        if (_servers.ContainsKey(server.Name))
        {
            _logger.LogWarning("Duplicate server name {Name} ignored", server.Name);
            return;
        }
        _servers[server.Name] = server;
    }

    /// <summary>
    /// Walks a directory for *.rdg files (RDCMan v2.x XML) and merges any &lt;server&gt; entries
    /// into the inventory. RDCMan is Windows-only, so all imported servers are flagged
    /// os=windows. Imported credentials are NOT auto-protected (the .rdg file is the source of
    /// truth — re-importing on next boot would re-add them).
    /// </summary>
    private void ImportRdg(string rdgDir)
    {
        if (!Directory.Exists(rdgDir))
        {
            _logger.LogWarning("RDG import path {Path} does not exist; skipping", rdgDir);
            return;
        }

        var files = Directory.GetFiles(rdgDir, "*.rdg", SearchOption.AllDirectories);
        foreach (var file in files)
        {
            try
            {
                var doc = XDocument.Load(file);
                var fileRoot = doc.Root?.Element("file");
                if (fileRoot is null)
                {
                    _logger.LogWarning("Skipping {File}: no <file> root element", file);
                    continue;
                }
                ImportRdgGroup(fileRoot, parentCreds: null, path: new List<string>());
                _logger.LogInformation("Imported RDG file {File}", file);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to import RDG file {File}", file);
            }
        }
    }

    private void ImportRdgGroup(XElement groupNode, ServerCredentials? parentCreds, List<string> path)
    {
        var groupCreds = ReadRdgCreds(groupNode) ?? parentCreds;
        var groupName = groupNode.Element("properties")?.Element("name")?.Value;
        var nextPath = string.IsNullOrWhiteSpace(groupName) ? path : new List<string>(path) { groupName };

        foreach (var server in groupNode.Elements("server"))
        {
            var props = server.Element("properties");
            var name = props?.Element("displayName")?.Value
                       ?? props?.Element("name")?.Value
                       ?? props?.Element("hostname")?.Value
                       ?? string.Empty;
            var host = props?.Element("name")?.Value
                       ?? props?.Element("hostname")?.Value
                       ?? name;
            if (string.IsNullOrWhiteSpace(name))
                continue;

            var resolved = new ResolvedServer
            {
                Name = name,
                Host = host,
                Os = "windows",
                Description = props?.Element("comment")?.Value,
                GroupPath = new List<string>(nextPath),
                // RDG creds are passed through as-is; ResolveCredentials happily handles a
                // ServerCredentials with no protected fields.
                Credentials = ResolveCredentials(ReadRdgCreds(server) ?? groupCreds, name),
            };
            AddOrWarn(resolved);
        }

        foreach (var child in groupNode.Elements("group"))
            ImportRdgGroup(child, groupCreds, nextPath);
    }

    private static ServerCredentials? ReadRdgCreds(XElement node)
    {
        var creds = node.Element("logonCredentials");
        if (creds is null) return null;
        var inherit = (string?)creds.Attribute("inherit");
        if (string.Equals(inherit, "FromParent", StringComparison.OrdinalIgnoreCase))
            return null;

        var domain = creds.Element("domain")?.Value;
        var user = creds.Element("userName")?.Value;
        var password = creds.Element("password")?.Value; // RDCMan stores DPAPI-encrypted; surface as-is.
        if (string.IsNullOrWhiteSpace(domain) && string.IsNullOrWhiteSpace(user) && string.IsNullOrWhiteSpace(password))
            return null;
        return new ServerCredentials { Domain = domain, Username = user, Password = password };
    }
}

internal static class JsonOpts
{
    public static readonly JsonSerializerOptions Read = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>Writes inventory files back out with omitted nulls so the on-disk shape stays clean.</summary>
    public static readonly JsonSerializerOptions Write = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };
}
