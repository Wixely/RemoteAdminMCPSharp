using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace RemoteAdminMCPSharp.Configuration;

/// <summary>
/// AES-256-GCM encryption with a key stored in a file on disk. Cross-platform equivalent of DPAPI
/// LocalMachine scope: the file-system permissions on the key file ARE the trust boundary.
///
/// Output format (base64): version-byte (0x01) || 12-byte nonce || ciphertext || 16-byte tag.
/// </summary>
public sealed class AesGcmKeyFileCredentialProtector : ICredentialProtector
{
    public const int KeyLengthBytes = 32;          // AES-256
    private const int NonceLengthBytes = 12;       // AES-GCM standard
    private const int TagLengthBytes = 16;         // AES-GCM standard
    private const byte FormatVersion = 0x01;

    private readonly string _keyPath;
    private readonly ILogger<AesGcmKeyFileCredentialProtector> _logger;
    private readonly Lazy<byte[]> _key;

    public AesGcmKeyFileCredentialProtector(
        string keyPath,
        ILogger<AesGcmKeyFileCredentialProtector> logger)
    {
        _keyPath = keyPath;
        _logger = logger;
        _key = new Lazy<byte[]>(LoadOrCreateKey);
    }

    public string Scheme => "aesgcm-keyfile";

    public string Protect(string plaintext)
    {
        var plain = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(NonceLengthBytes);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagLengthBytes];

        using var aes = new AesGcm(_key.Value, TagLengthBytes);
        aes.Encrypt(nonce, plain, cipher, tag);

        var output = new byte[1 + NonceLengthBytes + cipher.Length + TagLengthBytes];
        output[0] = FormatVersion;
        Buffer.BlockCopy(nonce, 0, output, 1, NonceLengthBytes);
        Buffer.BlockCopy(cipher, 0, output, 1 + NonceLengthBytes, cipher.Length);
        Buffer.BlockCopy(tag, 0, output, 1 + NonceLengthBytes + cipher.Length, TagLengthBytes);

        return Convert.ToBase64String(output);
    }

    public string Unprotect(string ciphertext)
    {
        var blob = Convert.FromBase64String(ciphertext);
        if (blob.Length < 1 + NonceLengthBytes + TagLengthBytes)
            throw new CryptographicException("Protected blob is too short.");
        if (blob[0] != FormatVersion)
            throw new CryptographicException($"Unsupported protected-blob version: 0x{blob[0]:X2}");

        var nonce = new byte[NonceLengthBytes];
        Buffer.BlockCopy(blob, 1, nonce, 0, NonceLengthBytes);

        var cipherLength = blob.Length - 1 - NonceLengthBytes - TagLengthBytes;
        var cipher = new byte[cipherLength];
        Buffer.BlockCopy(blob, 1 + NonceLengthBytes, cipher, 0, cipherLength);

        var tag = new byte[TagLengthBytes];
        Buffer.BlockCopy(blob, 1 + NonceLengthBytes + cipherLength, tag, 0, TagLengthBytes);

        var plain = new byte[cipherLength];
        using var aes = new AesGcm(_key.Value, TagLengthBytes);
        aes.Decrypt(nonce, cipher, tag, plain);

        return Encoding.UTF8.GetString(plain);
    }

    private byte[] LoadOrCreateKey()
    {
        var dir = Path.GetDirectoryName(_keyPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        if (File.Exists(_keyPath))
        {
            var existing = File.ReadAllBytes(_keyPath);
            if (existing.Length != KeyLengthBytes)
                throw new CryptographicException(
                    $"Key file at {_keyPath} is {existing.Length} bytes; expected {KeyLengthBytes}. " +
                    "Delete it to regenerate (this invalidates all currently-protected secrets).");
            return existing;
        }

        var newKey = RandomNumberGenerator.GetBytes(KeyLengthBytes);
        File.WriteAllBytes(_keyPath, newKey);
        // Lock down permissions on Linux/macOS — owner read+write only. No-op on Windows where
        // NTFS ACLs from the parent directory apply instead.
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            File.SetUnixFileMode(_keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        _logger.LogWarning(
            "Generated new AES-GCM master key at {KeyPath}. " +
            "BACK THIS UP — losing the key file makes every protected credential unrecoverable.",
            _keyPath);
        return newKey;
    }
}
