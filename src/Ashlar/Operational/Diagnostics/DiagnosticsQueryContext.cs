namespace Ashlar.Operational.Diagnostics;

internal sealed class DiagnosticsQueryContext<TConnection, TSnapshot>
    where TConnection : IAsyncDisposable
{
    public required Func<CancellationToken, ValueTask<TConnection>> OpenConnectionAsync { get; init; }

    public required Func<TConnection, CancellationToken, Task<bool>> TableExistsAsync { get; init; }

    public required Func<TConnection, DateTimeOffset, CancellationToken, Task<TSnapshot>> QuerySnapshotAsync { get; init; }

    public required Action<Exception> LogException { get; init; }

    public required string MissingTableReason { get; init; }

    public required string UnknownReason { get; init; }
}
