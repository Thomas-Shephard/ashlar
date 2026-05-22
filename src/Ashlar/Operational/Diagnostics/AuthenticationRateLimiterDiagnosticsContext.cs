namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents provider-specific operations used by authentication rate limiter diagnostics.
/// </summary>
/// <typeparam name="TConnection">The provider connection type.</typeparam>
/// <param name="OpenConnectionAsync">Opens a provider connection.</param>
/// <param name="TableExistsAsync">Checks whether the rate limiter table exists.</param>
/// <param name="QuerySnapshotAsync">Queries safe aggregate rate limiter state.</param>
/// <param name="LogException">Logs provider exceptions safely.</param>
public sealed record AuthenticationRateLimiterDiagnosticsContext<TConnection>(
    Func<CancellationToken, ValueTask<TConnection>> OpenConnectionAsync,
    Func<TConnection, CancellationToken, Task<bool>> TableExistsAsync,
    Func<TConnection, DateTimeOffset, CancellationToken, Task<AuthenticationRateLimiterDiagnosticSnapshot>> QuerySnapshotAsync,
    Action<Exception> LogException)
    where TConnection : IAsyncDisposable;
