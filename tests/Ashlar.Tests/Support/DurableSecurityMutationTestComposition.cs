using Ashlar.Auditing;

namespace Ashlar.Tests.Support;

internal sealed class DurableSecurityMutationTestComposition
{
    private static readonly RecordingTransactionProvider SharedTransactionProvider = new();
    private static readonly SecurityEventFanOutSink SharedEventSink = CreateEvents(new NullSecurityEventSink(), SharedTransactionProvider);

    public DurableSecurityMutationTestComposition(ISecurityEventSink? sink = null)
    {
        Transactions = new RecordingTransactionProvider();
        Events = new SecurityEventFanOutSink(new PersistentSink(sink ?? new NullSecurityEventSink()), transactionProvider: Transactions);
    }

    public RecordingTransactionProvider Transactions { get; }
    public SecurityEventFanOutSink Events { get; }

    public static IAshlarDurableTransactionProvider SharedTransactions => SharedTransactionProvider;
    public static SecurityEventFanOutSink SharedEvents => SharedEventSink;

    public static SecurityEventFanOutSink EventsFor(ISecurityEventSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        return CreateEvents(sink, SharedTransactionProvider);
    }

    public static SecurityEventFanOutSink EventsFor(ISecurityEventSink sink, IAshlarDurableTransactionProvider transactions)
    {
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(transactions);
        return new SecurityEventFanOutSink(new PersistentSink(sink), transactionProvider: transactions);
    }

    public static DurableSecurityMutationTestComposition Create(RecordingTransactionProvider transactions, ISecurityEventSink? sink = null)
    {
        ArgumentNullException.ThrowIfNull(transactions);
        return new DurableSecurityMutationTestComposition(transactions, sink);
    }

    private DurableSecurityMutationTestComposition(RecordingTransactionProvider transactions, ISecurityEventSink? sink)
    {
        Transactions = transactions;
        Events = CreateEvents(sink ?? new NullSecurityEventSink(), Transactions);
    }

    private static SecurityEventFanOutSink CreateEvents(ISecurityEventSink sink, RecordingTransactionProvider transactions) =>
        new(new PersistentSink(sink), transactionProvider: transactions);

    private sealed class PersistentSink(ISecurityEventSink inner) : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => inner.RecordAsync(securityEvent, cancellationToken);
    }
}
