using System.Collections.ObjectModel;
using System.Globalization;
using System.Management.Automation;
using System.Runtime.Versioning;
using System.Security;
using Microsoft.Extensions.Options;
using RemoteAdminMCPSharp.Configuration;

namespace RemoteAdminMCPSharp.Services;

/// <summary>
/// Runs PowerShell scripts against a remote Windows host via PowerShell Remoting (WSMan/WinRM,
/// HTTP 5985 / HTTPS 5986). Replaces the older WMI-over-DCOM transport.
///
/// Targets must have WinRM enabled (Enable-PSRemoting -Force) and the caller must be reachable
/// over WinRM — for non-domain hosts that usually means HTTPS or TrustedHosts.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PowerShellRemoteExecutor
{
    private readonly ConcurrencyGate _gate;
    private readonly TimeSpan _defaultTimeout;

    public PowerShellRemoteExecutor(ConcurrencyGate gate, IOptions<RemoteAdminOptions> options)
    {
        _gate = gate;
        _defaultTimeout = TimeSpan.FromSeconds(
            Math.Max(1, options.Value.RemoteOperationTimeoutSeconds));
    }

    /// <summary>
    /// Run a PowerShell script on the remote host and return the result as JSON.
    /// </summary>
    /// <param name="scriptBody">
    /// PowerShell script to execute remotely. May begin with <c>param(...)</c> if you need to bind
    /// values from <paramref name="args"/> — those flow in via WinRM's <c>-ArgumentList</c>.
    /// </param>
    /// <param name="args">
    /// Positional arguments. Bound to the script's <c>param(...)</c> block in order.
    /// </param>
    /// <param name="jsonDepth"><c>ConvertTo-Json -Depth</c>. Default 4.</param>
    public string InvokeRemoteJson(
        ResolvedServer server,
        string scriptBody,
        IReadOnlyList<object?>? args = null,
        int jsonDepth = 4)
    {
        EnsureWindows(server);

        using var _ = _gate.Acquire(server.Name);

        // Run the script remotely. PSRemoting serialises results back into local PSObjects so we
        // can pipe them into ConvertTo-Json on this side (PS 7 — supports -AsArray, unlike the
        // 5.1 ConvertTo-Json that may live on legacy targets).
        var remoteResults = InvokeRemote(server, scriptBody, args);
        return SerializeToJson(remoteResults, jsonDepth);
    }

    /// <summary>
    /// Run a PowerShell script on the remote host with request cancellation and a hard timeout.
    /// Stopping the local pipeline also stops the associated Invoke-Command remote pipeline, so
    /// remote file and event-log handles are released by their script-level finally blocks.
    /// </summary>
    public async Task<string> InvokeRemoteJsonAsync(
        ResolvedServer server,
        string scriptBody,
        IReadOnlyList<object?>? args = null,
        int jsonDepth = 4,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        EnsureWindows(server);

        var effectiveTimeout = timeout ?? _defaultTimeout;
        using var timeoutSource = new CancellationTokenSource(effectiveTimeout);
        using var linkedSource = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeoutSource.Token);
        try
        {
            using var gateLease = await _gate.AcquireAsync(server.Name, linkedSource.Token)
                .ConfigureAwait(false);
            var remoteResults = await InvokeRemoteAsync(
                server,
                scriptBody,
                args,
                linkedSource.Token).ConfigureAwait(false);
            return SerializeToJson(remoteResults, jsonDepth);
        }
        catch (PipelineStoppedException) when (linkedSource.IsCancellationRequested)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(
                    "The remote operation was cancelled by the caller.",
                    cancellationToken);
            }

            throw new TimeoutException(
                $"Remote invocation on '{server.Host}' exceeded its " +
                $"{effectiveTimeout.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)}-second timeout.");
        }
        catch (OperationCanceledException) when (
            timeoutSource.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"Remote invocation on '{server.Host}' exceeded its " +
                $"{effectiveTimeout.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)}-second timeout.");
        }
    }

    private static Collection<PSObject> InvokeRemote(
        ResolvedServer server,
        string scriptBody,
        IReadOnlyList<object?>? args)
    {
        using var ps = PowerShell.Create();
        var scriptBlock = ScriptBlock.Create(scriptBody);

        ps.AddCommand("Invoke-Command")
          .AddParameter("ComputerName", server.Host)
          .AddParameter("ScriptBlock", scriptBlock);

        var cred = ToCredential(server.Credentials);
        if (cred is not null)
            ps.AddParameter("Credential", cred);

        if (args is { Count: > 0 })
            ps.AddParameter("ArgumentList", args.ToArray());

        var results = ps.Invoke();

        if (ps.HadErrors)
        {
            var errors = string.Join("\n", ps.Streams.Error.Select(e => e.ToString()));
            throw new InvalidOperationException(
                $"Remote invocation on '{server.Host}' returned errors:\n{errors}");
        }
        return results;
    }

    private static async Task<Collection<PSObject>> InvokeRemoteAsync(
        ResolvedServer server,
        string scriptBody,
        IReadOnlyList<object?>? args,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using var ps = PowerShell.Create();
        ConfigureRemoteInvocation(ps, server, scriptBody, args);

        var invocation = ps.BeginInvoke();
        using var registration = cancellationToken.Register(static state =>
        {
            try
            {
                ((PowerShell)state!).Stop();
            }
            catch (ObjectDisposedException)
            {
                // Completion won the race with cancellation.
            }
            catch (InvalidPowerShellStateException)
            {
                // The pipeline already completed or stopped.
            }
        }, ps);

        var results = await Task<PSDataCollection<PSObject>>.Factory.FromAsync(
            invocation,
            ps.EndInvoke).ConfigureAwait(false);

        if (ps.HadErrors)
        {
            var errors = string.Join("\n", ps.Streams.Error.Select(e => e.ToString()));
            throw new InvalidOperationException(
                $"Remote invocation on '{server.Host}' returned errors:\n{errors}");
        }

        return new Collection<PSObject>(results.ToList());
    }

    private static void ConfigureRemoteInvocation(
        PowerShell ps,
        ResolvedServer server,
        string scriptBody,
        IReadOnlyList<object?>? args)
    {
        var scriptBlock = ScriptBlock.Create(scriptBody);

        ps.AddCommand("Invoke-Command")
          .AddParameter("ComputerName", server.Host)
          .AddParameter("ScriptBlock", scriptBlock);

        var cred = ToCredential(server.Credentials);
        if (cred is not null)
            ps.AddParameter("Credential", cred);

        if (args is { Count: > 0 })
            ps.AddParameter("ArgumentList", args.ToArray());
    }

    private static string SerializeToJson(Collection<PSObject> input, int depth)
    {
        if (input.Count == 0) return "[]";

        using var ps = PowerShell.Create();
        // Pass the entire result set as a single -InputObject (an array) instead of feeding items
        // through the pipeline. Pipeline binding (Invoke(IEnumerable)) has been observed to throw
        // ParameterBindingException on Deserialized.* PSObjects returned from remote runspaces
        // when the collection contains a mix of types (e.g. Win32_Service projection that includes
        // a null ProcessId on stopped services). Direct InputObject binding sidesteps that — the
        // cmdlet sees one array argument and produces a JSON array. -AsArray is no longer needed.
        ps.AddCommand("ConvertTo-Json")
          .AddParameter("InputObject", input.ToArray())
          .AddParameter("Depth", depth)
          .AddParameter("Compress");

        Collection<PSObject> json;
        try
        {
            json = ps.Invoke();
        }
        catch (Exception ex)
        {
            // ParameterBindingException etc. lose their detail by the time they surface to the
            // agent — wrap with context so the actual cause shows up in logs.
            throw new InvalidOperationException(
                $"ConvertTo-Json (local) threw {ex.GetType().Name} while serialising {input.Count} object(s): {ex.Message}",
                ex);
        }
        if (ps.HadErrors)
        {
            var errors = string.Join("\n", ps.Streams.Error.Select(e => e.ToString()));
            throw new InvalidOperationException(
                $"ConvertTo-Json (local) failed:\n{errors}");
        }
        return string.Concat(json.Select(r => r?.BaseObject?.ToString())) ?? "[]";
    }

    private static PSCredential? ToCredential(ServerCredentials? creds)
    {
        if (creds is null || string.IsNullOrWhiteSpace(creds.Username))
            return null;

        var user = string.IsNullOrWhiteSpace(creds.Domain)
            ? creds.Username
            : $"{creds.Domain}\\{creds.Username}";

        var secure = new SecureString();
        foreach (var c in creds.Password ?? string.Empty)
            secure.AppendChar(c);
        secure.MakeReadOnly();
        return new PSCredential(user, secure);
    }

    private static void EnsureWindows(ResolvedServer server)
    {
        if (!string.Equals(server.Os, "windows", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"Server '{server.Name}' is not a Windows host (os={server.Os}). " +
                "Linux remoting requires PowerShell-over-SSH and isn't wired up yet.");
    }
}
