using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ModelContextProtocol;
using RemoteAdminMCPSharp.Configuration;

namespace RemoteAdminMCPSharp.Services;

/// <summary>
/// Enforces the per-server and global concurrency caps configured under
/// <c>RemoteAdmin:Concurrency</c>, plus an optional minimum interval between operations against
/// the same server. Call sites use <c>using var _ = gate.Acquire(server.Name)</c>; the disposable
/// releases both semaphores and stamps the per-server "last release" time for rate-spacing.
/// </summary>
public sealed class ConcurrencyGate
{
    private readonly ConcurrencyOptions _options;
    private readonly ILogger<ConcurrencyGate> _logger;
    private readonly SemaphoreSlim _global;
    private readonly ConcurrentDictionary<string, PerServerGate> _perServer =
        new(StringComparer.OrdinalIgnoreCase);

    public ConcurrencyGate(IOptions<RemoteAdminOptions> options, ILogger<ConcurrencyGate> logger)
    {
        _options = options.Value.Concurrency ?? new ConcurrencyOptions();
        _logger = logger;
        _global = new SemaphoreSlim(Math.Max(1, _options.MaxConcurrentGlobal));
    }

    public IDisposable Acquire(string serverName)
    {
        var timeout = TimeSpan.FromSeconds(Math.Max(1, _options.AcquireTimeoutSeconds));
        var perServer = _perServer.GetOrAdd(serverName,
            _ => new PerServerGate(Math.Max(1, _options.MaxConcurrentPerServer)));

        // Enforce the rate-limit floor BEFORE we acquire any semaphore — otherwise we'd be
        // sleeping while holding a slot, starving other servers.
        WaitForRateLimitWindow(perServer, serverName);

        if (!_global.Wait(timeout))
        {
            throw new McpException(
                $"MCP server concurrency cap reached: could not acquire a global slot within " +
                $"{timeout.TotalSeconds:F0}s (RemoteAdmin:Concurrency:MaxConcurrentGlobal={_options.MaxConcurrentGlobal}). " +
                "Too many parallel tool calls are in flight. Back off and retry.");
        }

        if (!perServer.Semaphore.Wait(timeout))
        {
            _global.Release();
            throw new McpException(
                $"MCP server concurrency cap reached for server '{serverName}': could not acquire a " +
                $"per-server slot within {timeout.TotalSeconds:F0}s " +
                $"(RemoteAdmin:Concurrency:MaxConcurrentPerServer={_options.MaxConcurrentPerServer}). " +
                "Wait for the previous call against this host to complete.");
        }

        return new Releaser(this, perServer);
    }

    /// <summary>
    /// Asynchronously acquires the same global and per-server slots as <see cref="Acquire"/>,
    /// while allowing an MCP request cancellation to interrupt queue and rate-limit waits.
    /// </summary>
    public async Task<IDisposable> AcquireAsync(
        string serverName,
        CancellationToken cancellationToken = default)
    {
        var timeout = TimeSpan.FromSeconds(Math.Max(1, _options.AcquireTimeoutSeconds));
        var perServer = _perServer.GetOrAdd(serverName,
            _ => new PerServerGate(Math.Max(1, _options.MaxConcurrentPerServer)));

        await WaitForRateLimitWindowAsync(perServer, serverName, cancellationToken)
            .ConfigureAwait(false);

        if (!await _global.WaitAsync(timeout, cancellationToken).ConfigureAwait(false))
        {
            throw new McpException(
                $"MCP server concurrency cap reached: could not acquire a global slot within " +
                $"{timeout.TotalSeconds:F0}s (RemoteAdmin:Concurrency:MaxConcurrentGlobal={_options.MaxConcurrentGlobal}). " +
                "Too many parallel tool calls are in flight. Back off and retry.");
        }

        try
        {
            if (!await perServer.Semaphore.WaitAsync(timeout, cancellationToken).ConfigureAwait(false))
            {
                throw new McpException(
                    $"MCP server concurrency cap reached for server '{serverName}': could not acquire a " +
                    $"per-server slot within {timeout.TotalSeconds:F0}s " +
                    $"(RemoteAdmin:Concurrency:MaxConcurrentPerServer={_options.MaxConcurrentPerServer}). " +
                    "Wait for the previous call against this host to complete.");
            }
        }
        catch
        {
            _global.Release();
            throw;
        }

        return new Releaser(this, perServer);
    }

    private void WaitForRateLimitWindow(PerServerGate gate, string serverName)
    {
        var intervalMs = _options.MinIntervalPerServerMs;
        if (intervalMs <= 0) return;

        var lastRelease = Interlocked.Read(ref gate.LastReleaseTicks);
        if (lastRelease == 0) return; // first call against this server

        var elapsed = Environment.TickCount64 - lastRelease;
        var waitMs = intervalMs - elapsed;
        if (waitMs <= 0) return;

        _logger.LogDebug("Rate-limit: holding next op against {Server} for {Wait}ms", serverName, waitMs);
        Thread.Sleep((int)Math.Min(waitMs, int.MaxValue));
    }

    private async Task WaitForRateLimitWindowAsync(
        PerServerGate gate,
        string serverName,
        CancellationToken cancellationToken)
    {
        var intervalMs = _options.MinIntervalPerServerMs;
        if (intervalMs <= 0) return;

        var lastRelease = Interlocked.Read(ref gate.LastReleaseTicks);
        if (lastRelease == 0) return;

        var elapsed = Environment.TickCount64 - lastRelease;
        var waitMs = intervalMs - elapsed;
        if (waitMs <= 0) return;

        _logger.LogDebug("Rate-limit: holding next op against {Server} for {Wait}ms", serverName, waitMs);
        await Task.Delay(TimeSpan.FromMilliseconds(waitMs), cancellationToken).ConfigureAwait(false);
    }

    private sealed class PerServerGate
    {
        public SemaphoreSlim Semaphore { get; }
        public long LastReleaseTicks; // Environment.TickCount64

        public PerServerGate(int maxConcurrent)
        {
            Semaphore = new SemaphoreSlim(maxConcurrent, maxConcurrent);
        }
    }

    private sealed class Releaser : IDisposable
    {
        private readonly ConcurrencyGate _gate;
        private readonly PerServerGate _perServer;
        private bool _disposed;

        public Releaser(ConcurrencyGate gate, PerServerGate perServer)
        {
            _gate = gate;
            _perServer = perServer;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            // Stamp release time first so a concurrent acquirer sees a fresh interval start.
            Interlocked.Exchange(ref _perServer.LastReleaseTicks, Environment.TickCount64);
            _perServer.Semaphore.Release();
            _gate._global.Release();
        }
    }
}
