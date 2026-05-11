namespace RemoteAdminMCPSharp.Configuration;

/// <summary>
/// Bounds on how aggressively agents can drive remote operations. Two complementary knobs:
/// concurrency caps parallel work, and an optional per-server minimum interval enforces a
/// floor on time-between-calls (rate-limit).
/// </summary>
public sealed class ConcurrencyOptions
{
    /// <summary>
    /// Max concurrent remote operations against any single server. Default 1 — most conservative,
    /// also avoids common pitfalls like WinRM session contention or stepping on yourself with a
    /// stop-then-start service pair.
    /// </summary>
    public int MaxConcurrentPerServer { get; set; } = 1;

    /// <summary>Max concurrent remote operations across the entire inventory.</summary>
    public int MaxConcurrentGlobal { get; set; } = 16;

    /// <summary>
    /// How long to wait for a slot before giving up. The remote operation itself has its own
    /// timeout (see <see cref="RemoteAdminOptions.RemoteOperationTimeoutSeconds"/>) — this is
    /// just for the queue wait.
    /// </summary>
    public int AcquireTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Optional rate-limit: minimum milliseconds between the end of one operation against a
    /// server and the start of the next against the same server. 0 disables. Useful if your
    /// concern is sustained frequency rather than parallelism.
    /// </summary>
    public int MinIntervalPerServerMs { get; set; } = 0;
}
