using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.Runtime.Versioning;
using RemoteAdminMCPSharp.Configuration;
using RemoteAdminMCPSharp.Services;
using Xunit;

namespace RemoteAdminMCPSharp.Tests;

[SupportedOSPlatform("windows")]
public sealed class PowerShellRemoteExecutorTests
{
    [Fact]
    public async Task TimeoutWhileWaitingForConcurrencySlotIsReportedAsTimeout()
    {
        var options = Options.Create(new RemoteAdminOptions
        {
            Concurrency = new ConcurrencyOptions
            {
                MaxConcurrentGlobal = 1,
                MaxConcurrentPerServer = 1,
                AcquireTimeoutSeconds = 30,
            },
        });
        var gate = new ConcurrencyGate(options, NullLogger<ConcurrencyGate>.Instance);
        var executor = new PowerShellRemoteExecutor(gate, options);
        var server = new ResolvedServer
        {
            Name = "blocked-server",
            Host = "127.0.0.1",
            Os = "windows",
        };

        using var heldSlot = gate.Acquire(server.Name);

        var exception = await Assert.ThrowsAsync<TimeoutException>(() =>
            executor.InvokeRemoteJsonAsync(
                server,
                "'not reached'",
                timeout: TimeSpan.FromMilliseconds(100)));

        Assert.Contains("exceeded its 0.1-second timeout", exception.Message);
    }
}
