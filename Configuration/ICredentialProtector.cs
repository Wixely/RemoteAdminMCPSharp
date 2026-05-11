namespace RemoteAdminMCPSharp.Configuration;

/// <summary>
/// Symmetric protector for short secrets (passwords, key passphrases). Implementations choose
/// where the key material lives; the encoded output is opaque base64 you can put in JSON.
/// </summary>
public interface ICredentialProtector
{
    /// <summary>
    /// Stable identifier written next to a protected blob so we can pick the right protector to
    /// decrypt it. Examples: <c>dpapi-user</c>, <c>dpapi-machine</c>, <c>aesgcm-keyfile</c>.
    /// </summary>
    string Scheme { get; }

    string Protect(string plaintext);

    string Unprotect(string ciphertext);
}
