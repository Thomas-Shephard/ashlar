namespace Ashlar.Auditing;

internal static class DurableSecurityMutationComposition
{
    public static SecurityEventFanOutSink Require(
        SecurityEventFanOutSink? securityEventSink,
        IAshlarDurableTransactionProvider? transactionProvider,
        string operation)
    {
        ArgumentNullException.ThrowIfNull(securityEventSink);
        ArgumentNullException.ThrowIfNull(transactionProvider);

        if (!securityEventSink.RequiresDurableTransaction || !ReferenceEquals(transactionProvider, securityEventSink.TransactionProvider))
        {
            throw new ArgumentException($"{operation} requires durable audit using the same transaction provider.");
        }

        return securityEventSink;
    }
}
