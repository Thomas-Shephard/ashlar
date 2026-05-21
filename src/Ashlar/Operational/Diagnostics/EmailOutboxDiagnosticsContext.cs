namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents provider-specific email outbox diagnostics operations.
/// </summary>
/// <typeparam name="TConnection">The provider connection type.</typeparam>
/// <param name="OpenConnectionAsync">The open connection callback.</param>
/// <param name="TableExistsAsync">The table exists callback.</param>
/// <param name="QuerySnapshotAsync">The snapshot query callback.</param>
/// <param name="LogException">The exception logging callback.</param>
public sealed record EmailOutboxDiagnosticsContext<TConnection>(
    Func<CancellationToken, ValueTask<TConnection>> OpenConnectionAsync,
    Func<TConnection, CancellationToken, Task<bool>> TableExistsAsync,
    Func<TConnection, DateTimeOffset, CancellationToken, Task<EmailOutboxDiagnosticSnapshot>> QuerySnapshotAsync,
    Action<Exception> LogException)
    where TConnection : IAsyncDisposable;
