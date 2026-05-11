using RemoteAdminMCPSharp.Configuration;

namespace RemoteAdminMCPSharp.Services;

/// <summary>
/// Holds the active protector (used to encrypt new plaintexts) plus a registry of every
/// available protector keyed by scheme (used to decrypt existing blobs, including blobs written
/// by a different scheme on a previous boot — useful when migrating between schemes).
/// </summary>
public sealed class CredentialProtectionService
{
    private readonly Dictionary<string, ICredentialProtector> _byScheme;
    private readonly ICredentialProtector? _active;

    public CredentialProtectionService(IEnumerable<ICredentialProtector> protectors, string activeScheme)
    {
        _byScheme = protectors.ToDictionary(p => p.Scheme, StringComparer.OrdinalIgnoreCase);

        if (string.Equals(activeScheme, "none", StringComparison.OrdinalIgnoreCase))
        {
            _active = null;
            return;
        }

        if (!_byScheme.TryGetValue(activeScheme, out _active))
        {
            throw new InvalidOperationException(
                $"Credential protection scheme '{activeScheme}' is not available on this platform. " +
                $"Available: [{string.Join(", ", _byScheme.Keys)}] or 'none' to disable.");
        }
    }

    /// <summary>True when an active protector is configured and the encrypt-on-startup pass should run.</summary>
    public bool IsEnabled => _active is not null;

    /// <summary>The scheme written into newly-protected blobs.</summary>
    public string ActiveScheme => _active?.Scheme ?? "none";

    public string Protect(string plaintext)
    {
        if (_active is null)
            throw new InvalidOperationException("Credential protection is disabled (CredentialProtection=none).");
        return _active.Protect(plaintext);
    }

    public string Unprotect(string ciphertext, string? scheme)
    {
        var schemeToUse = scheme ?? _active?.Scheme
            ?? throw new InvalidOperationException(
                "Cannot decrypt protected credential: no scheme recorded on the blob and no active protector.");

        if (!_byScheme.TryGetValue(schemeToUse, out var protector))
        {
            throw new InvalidOperationException(
                $"Inventory has a credential protected with scheme '{schemeToUse}' but that protector " +
                "isn't available on this host. Re-enter the plaintext to re-encrypt with the active scheme.");
        }
        return protector.Unprotect(ciphertext);
    }
}
