namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>Manages recovery codes through actor-bound, host-authorized requests.</summary>
/// <remarks>Revoking or expiring a proof's source session immediately invalidates the proof for every recovery-code mutation.</remarks>
public interface IRecoveryCodeService
{
    /// <summary>Generates recovery codes through an authorized destructive request.</summary>
    /// <param name="request">The actor, target, scope, proof, audit metadata, and generation options.</param>
    /// <param name="cancellationToken">Token for aborting generation.</param>
    /// <returns>Raw recovery codes to show once to the user. Do not log or persist them.</returns>
    Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesAsync(
        RecoveryCodeGenerationRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>Revokes recovery codes through an authorized destructive request.</summary>
    /// <param name="request">The actor, target, scope, proof, audit metadata, and reason.</param>
    /// <param name="cancellationToken">Token for aborting revocation.</param>
    /// <returns>The number of recovery-code credentials revoked.</returns>
    Task<Result<int>> RevokeRecoveryCodesAsync(
        RevokeRecoveryCodesRequest request,
        CancellationToken cancellationToken = default);
}
