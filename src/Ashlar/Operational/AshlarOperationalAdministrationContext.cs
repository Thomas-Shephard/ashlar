namespace Ashlar.Operational;

using Ashlar.Identity.Features.Administration;

/// <summary>Identifies the fixed authorization and audit boundaries for provider-backed operational administration.</summary>
public enum AshlarOperationalAdministrationKind
{
    /// <summary>Email outbox administration.</summary>
    EmailOutbox,
    /// <summary>Security-event webhook outbox administration.</summary>
    SecurityEventWebhookOutbox
}

/// <summary>Safe authorization and audit capabilities supplied to a provider's operational administration implementation.</summary>
/// <param name="readBoundary">The read-operation boundary.</param>
/// <param name="mutationBoundary">The mutation-operation boundary.</param>
public sealed class AshlarOperationalAdministrationContext(
    AccountSecurityOperationBoundary readBoundary,
    AccountSecurityOperationBoundary mutationBoundary)
{
    /// <summary>Gets the read-operation authorization and audit boundary.</summary>
    public AccountSecurityOperationBoundary ReadBoundary { get; } =
        readBoundary ?? throw new ArgumentNullException(nameof(readBoundary));

    /// <summary>Gets the mutation-operation authorization and audit boundary.</summary>
    public AccountSecurityOperationBoundary MutationBoundary { get; } =
        mutationBoundary ?? throw new ArgumentNullException(nameof(mutationBoundary));
}
