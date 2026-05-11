using Microsoft.Extensions.Options;
using Renci.SshNet;
using RemoteAdminMCPSharp.Configuration;

namespace RemoteAdminMCPSharp.Services;

/// <summary>
/// Runs shell commands against a remote Linux host over SSH. One-shot connections per call —
/// no pool yet, simple to reason about.
/// </summary>
public sealed class SshRemoteExecutor
{
    private readonly RemoteAdminOptions _options;
    private readonly ConcurrencyGate _gate;

    public SshRemoteExecutor(IOptions<RemoteAdminOptions> options, ConcurrencyGate gate)
    {
        _options = options.Value;
        _gate = gate;
    }

    /// <summary>
    /// Connects, runs <paramref name="command"/>, captures stdout/stderr/exit code, then disconnects.
    /// Throws if connection fails. Does NOT throw on non-zero exit — callers decide.
    /// </summary>
    public SshCommandResult InvokeRemote(ResolvedServer server, string command, TimeSpan? timeout = null)
    {
        EnsureLinux(server);
        var creds = server.Credentials
            ?? throw new InvalidOperationException(
                $"No credentials configured for Linux server '{server.Name}'.");

        var effectiveTimeout = timeout ?? TimeSpan.FromSeconds(Math.Max(1, _options.RemoteOperationTimeoutSeconds));

        using var _ = _gate.Acquire(server.Name);
        using var client = CreateClient(server, creds);
        client.ConnectionInfo.Timeout = effectiveTimeout;
        client.Connect();
        try
        {
            using var cmd = client.CreateCommand(command);
            cmd.CommandTimeout = effectiveTimeout;
            cmd.Execute();
            return new SshCommandResult(
                StdOut: cmd.Result ?? string.Empty,
                StdErr: cmd.Error ?? string.Empty,
                ExitCode: cmd.ExitStatus ?? -1);
        }
        finally
        {
            client.Disconnect();
        }
    }

    /// <summary>
    /// Like <see cref="InvokeRemote"/> but throws if the command exits non-zero, surfacing stderr.
    /// Use for "this must succeed" management operations (start/stop/restart, kill).
    /// </summary>
    public SshCommandResult InvokeRemoteOrThrow(ResolvedServer server, string command, TimeSpan? timeout = null)
    {
        var result = InvokeRemote(server, command, timeout);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Command on {server.Host} exited with code {result.ExitCode}.\nstderr: {result.StdErr}\nstdout: {result.StdOut}");
        }
        return result;
    }

    private static SshClient CreateClient(ResolvedServer server, ServerCredentials creds)
    {
        var port = creds.Port ?? 22;
        var username = creds.Username
            ?? throw new InvalidOperationException(
                $"Username required for SSH server '{server.Name}'.");

        if (!string.IsNullOrWhiteSpace(creds.PrivateKeyPath))
        {
            if (!File.Exists(creds.PrivateKeyPath))
            {
                throw new InvalidOperationException(
                    $"Private key file not found: {creds.PrivateKeyPath}");
            }
            var keyFile = string.IsNullOrEmpty(creds.PrivateKeyPassphrase)
                ? new PrivateKeyFile(creds.PrivateKeyPath)
                : new PrivateKeyFile(creds.PrivateKeyPath, creds.PrivateKeyPassphrase);
            return new SshClient(server.Host, port, username, keyFile);
        }

        if (!string.IsNullOrEmpty(creds.Password))
        {
            return new SshClient(server.Host, port, username, creds.Password);
        }

        throw new InvalidOperationException(
            $"SSH credentials for '{server.Name}' must include either a Password or a PrivateKeyPath.");
    }

    private static void EnsureLinux(ResolvedServer server)
    {
        if (!string.Equals(server.Os, "linux", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"Server '{server.Name}' is not a Linux host (os={server.Os}). Use the win_* tools instead.");
    }

    /// <summary>
    /// Shell-quote a value with single quotes. Use for splicing untrusted strings (service names,
    /// pids, etc.) into shell commands.
    /// </summary>
    public static string ShellQuote(string value)
        => "'" + (value ?? string.Empty).Replace("'", "'\\''") + "'";
}

public sealed record SshCommandResult(string StdOut, string StdErr, int ExitCode);
