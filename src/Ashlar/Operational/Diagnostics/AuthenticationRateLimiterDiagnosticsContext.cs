namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Bundles provider-specific authentication rate limiter diagnostics callbacks.
/// </summary>
/// <typeparam name="TConnection">Provider connection type used by diagnostics callbacks.</typeparam>
/// <param name="OpenConnectionAsync">Callback that opens a provider connection for diagnostics.</param>
/// <param name="TableExistsAsync">Callback that checks whether the rate limiter table exists.</param>
/// <param name="QuerySnapshotAsync">Callback that reads aggregate limiter state without exposing raw rate-limit keys.</param>
/// <param name="LogException">Callback that records diagnostics failures without exposing provider query details.</param>
public sealed record AuthenticationRateLimiterDiagnosticsContext<TConnection>(
    Func<CancellationToken, ValueTask<TConnection>> OpenConnectionAsync,
    Func<TConnection, CancellationToken, Task<bool>> TableExistsAsync,
    Func<TConnection, DateTimeOffset, CancellationToken, Task<AuthenticationRateLimiterDiagnosticSnapshot>> QuerySnapshotAsync,
    Action<Exception> LogException)
    where TConnection : IAsyncDisposable;
