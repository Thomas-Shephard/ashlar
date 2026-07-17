using Ashlar.Auditing;

namespace Ashlar.Tests.Support;

internal sealed class DurableSecurityMutationTestComposition
{
    public DurableSecurityMutationTestComposition(ISecurityEventSink? sink = null, params object[] participants)
    {
        RawTransactions = new RecordingTransactionProvider();
        (Transactions, Events) = CreateEvents(sink ?? new NullSecurityEventSink(), RawTransactions, participants);
    }

    public RecordingTransactionProvider RawTransactions { get; }
    public AshlarDurableTransactionProvider Transactions { get; }
    public SecurityEventFanOutSink Events { get; }

    public static DurableSecurityMutationTestComposition Create(RecordingTransactionProvider transactions, ISecurityEventSink? sink = null, params object[] participants)
    {
        ArgumentNullException.ThrowIfNull(transactions);
        return new DurableSecurityMutationTestComposition(transactions, sink, participants);
    }

    public static (AshlarDurableTransactionProvider Transactions, SecurityEventFanOutSink Events) Compose(
        IAshlarTransactionProvider transactions,
        ISecurityEventSink sink,
        params object[] participants)
    {
        ArgumentNullException.ThrowIfNull(transactions);
        ArgumentNullException.ThrowIfNull(sink);
        return CreateEvents(sink, transactions, participants);
    }

    private DurableSecurityMutationTestComposition(RecordingTransactionProvider transactions, ISecurityEventSink? sink, object[] participants)
    {
        RawTransactions = transactions;
        (Transactions, Events) = CreateEvents(sink ?? new NullSecurityEventSink(), transactions, participants);
    }

    private static (AshlarDurableTransactionProvider Transactions, SecurityEventFanOutSink Events) CreateEvents(
        ISecurityEventSink sink, IAshlarTransactionProvider transactions, params object[] participants)
    {
        var persistent = new PersistentSink(sink);
        var composition = AshlarDurableTransactionProvider.Create(transactions, [persistent, .. participants]);
        return (composition, new SecurityEventFanOutSink(persistent, transactionProvider: composition));
    }

    private sealed class PersistentSink(ISecurityEventSink inner) : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => inner.RecordAsync(securityEvent, cancellationToken);
    }
}
