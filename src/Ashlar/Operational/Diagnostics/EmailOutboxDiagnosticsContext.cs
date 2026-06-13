namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Bundles provider-specific email outbox diagnostics callbacks.
/// </summary>
/// <typeparam name="TConnection">Provider connection type used by diagnostics callbacks.</typeparam>
/// <param name="OpenConnectionAsync">Callback that opens a provider connection for diagnostics.</param>
/// <param name="TableExistsAsync">Callback that checks whether the outbox table exists.</param>
/// <param name="QuerySnapshotAsync">Callback that reads aggregate outbox state without exposing message bodies.</param>
/// <param name="LogException">Callback that records diagnostics failures without exposing provider query details.</param>
public sealed record EmailOutboxDiagnosticsContext<TConnection>(
    Func<CancellationToken, ValueTask<TConnection>> OpenConnectionAsync,
    Func<TConnection, CancellationToken, Task<bool>> TableExistsAsync,
    Func<TConnection, DateTimeOffset, CancellationToken, Task<EmailOutboxDiagnosticSnapshot>> QuerySnapshotAsync,
    Action<Exception> LogException)
    where TConnection : IAsyncDisposable;
