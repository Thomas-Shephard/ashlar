using Ashlar.Identity.Abstractions.Transactions;

namespace Ashlar.Testing;

/// <summary>Creates exact durable transaction compositions for provider and service contract tests.</summary>
public static class DurableTransactionComposition
{
    /// <summary>Creates a test composition containing the supplied participant instances.</summary>
    public static AshlarDurableTransactionProvider Create(
        IAshlarTransactionProvider provider,
        params object[] participants) =>
        AshlarDurableTransactionProvider.Create(provider, participants);
}
