using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace RemoteAdminMCPSharp.Configuration;

/// <summary>
/// DPAPI under <see cref="DataProtectionScope.CurrentUser"/> — only the Windows account that
/// performed the protect call can unprotect. For a Windows Service this means the service
/// account must be the same that originally encrypted the values.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiCurrentUserCredentialProtector : ICredentialProtector
{
    public string Scheme => "dpapi-user";

    public string Protect(string plaintext)
    {
        var raw = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = ProtectedData.Protect(raw, optionalEntropy: null, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(ciphertext);
    }

    public string Unprotect(string ciphertext)
    {
        var raw = Convert.FromBase64String(ciphertext);
        var plain = ProtectedData.Unprotect(raw, optionalEntropy: null, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(plain);
    }
}

/// <summary>
/// DPAPI under <see cref="DataProtectionScope.LocalMachine"/> — any process on this machine can
/// unprotect. Easier to bootstrap than per-user scope but offers no protection against other
/// admins on the box.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiLocalMachineCredentialProtector : ICredentialProtector
{
    public string Scheme => "dpapi-machine";

    public string Protect(string plaintext)
    {
        var raw = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = ProtectedData.Protect(raw, optionalEntropy: null, DataProtectionScope.LocalMachine);
        return Convert.ToBase64String(ciphertext);
    }

    public string Unprotect(string ciphertext)
    {
        var raw = Convert.FromBase64String(ciphertext);
        var plain = ProtectedData.Unprotect(raw, optionalEntropy: null, DataProtectionScope.LocalMachine);
        return Encoding.UTF8.GetString(plain);
    }
}
