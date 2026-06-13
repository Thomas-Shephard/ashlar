namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Bundles provider-specific security event webhook outbox diagnostics callbacks.
/// </summary>
/// <typeparam name="TConnection">Provider connection type used by diagnostics callbacks.</typeparam>
/// <param name="OpenConnectionAsync">Callback that opens a provider connection for diagnostics.</param>
/// <param name="TableExistsAsync">Callback that checks whether the webhook outbox table exists.</param>
/// <param name="QuerySnapshotAsync">Callback that reads aggregate webhook outbox state without exposing payloads.</param>
/// <param name="LogException">Callback that records diagnostics failures without exposing provider query details.</param>
public sealed record SecurityEventWebhookOutboxDiagnosticsContext<TConnection>(
    Func<CancellationToken, ValueTask<TConnection>> OpenConnectionAsync,
    Func<TConnection, CancellationToken, Task<bool>> TableExistsAsync,
    Func<TConnection, DateTimeOffset, CancellationToken, Task<SecurityEventWebhookOutboxDiagnosticSnapshot>> QuerySnapshotAsync,
    Action<Exception> LogException)
    where TConnection : IAsyncDisposable;
