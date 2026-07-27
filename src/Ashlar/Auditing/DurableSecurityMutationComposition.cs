namespace Ashlar.Auditing;

internal static class DurableSecurityMutationComposition
{
    public static SecurityEventFanOutSink Require(
        SecurityEventFanOutSink? securityEventSink,
        AshlarDurableTransactionProvider? transactionProvider,
        string operation,
        params object[] participants)
    {
        ArgumentNullException.ThrowIfNull(securityEventSink);
        ArgumentNullException.ThrowIfNull(transactionProvider);

        if (!securityEventSink.RequiresDurableTransaction)
            throw new ArgumentException($"{operation} requires durable audit using the same transaction provider.");
        if (!ReferenceEquals(transactionProvider, securityEventSink.TransactionProvider))
            throw new ArgumentException($"{operation} requires durable audit using the same transaction provider.");
        if (participants.Any(participant => !transactionProvider.IncludesParticipant(participant)))
            throw new ArgumentException($"{operation} requires each repository and audit participant to be the exact instance enlisted by the persistence provider; DI decorators must be composed inside that transaction boundary.");

        return securityEventSink;
    }
}
