namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Validates fresh authentication proofs against their authoritative active session.</summary>
public interface IFreshAuthenticationProofValidator
{
    /// <summary>Validates an MFA proof against its authoritative active session.</summary>
    /// <param name="userId">Expected session user.</param>
    /// <param name="tenant">Expected session tenant.</param>
    /// <param name="proof">Proof to validate.</param>
    /// <param name="currentSessionId">Authenticated request session.</param>
    /// <param name="purpose">Required proof purpose.</param>
    /// <param name="cancellationToken">Token used to cancel session lookup.</param>
    /// <returns>A failure code, or <see langword="null" /> when valid.</returns>
    ValueTask<AshlarFailureCode?> ValidateAsync(Guid userId, TenantContext tenant,
        FreshMfaVerificationProof? proof, Guid? currentSessionId, string? purpose, CancellationToken cancellationToken);

    /// <summary>Validates a primary-authentication proof against its authoritative active session.</summary>
    /// <param name="userId">Expected session user.</param>
    /// <param name="tenant">Expected session tenant.</param>
    /// <param name="proof">Proof to validate.</param>
    /// <param name="currentSessionId">Authenticated request session.</param>
    /// <param name="purpose">Required proof purpose.</param>
    /// <param name="cancellationToken">Token used to cancel session lookup.</param>
    /// <returns>A failure code, or <see langword="null" /> when valid.</returns>
    ValueTask<AshlarFailureCode?> ValidateAsync(Guid userId, TenantContext tenant,
        FreshPrimaryAuthenticationProof? proof, Guid? currentSessionId, string? purpose, CancellationToken cancellationToken);
}
