namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Defines services for managing user recovery codes.
/// </summary>
public interface IRecoveryCodeService
{
    /// <summary>
    /// Generates a new set of recovery codes for the specified user.
    /// </summary>
    /// <param name="userId">User receiving the new recovery-code set.</param>
    /// <param name="request">Fresh MFA proof, generation options, tenant scope, and audit context for the operation.</param>
    /// <param name="cancellationToken">Token for aborting generation and persistence work.</param>
    /// <returns>Raw recovery codes to show once to the user. Do not log or persist these values outside Ashlar's hashed credentials.</returns>
    Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesAsync(Guid userId, RecoveryCodeGenerationRequest? request = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates recovery codes through an explicitly privileged recovery or administration path.
    /// </summary>
    /// <param name="userId">User receiving the new recovery-code set.</param>
    /// <param name="request">Generation options, tenant scope, and audit context for the operation.</param>
    /// <param name="cancellationToken">Token for aborting generation and persistence work.</param>
    /// <returns>Raw recovery codes to show once to the user. Do not log or persist these values outside Ashlar's hashed credentials.</returns>
    /// <remarks>
    /// This method does not require self-service fresh MFA proof. Call it only from already-authorized
    /// recovery or administration workflows with audit context; ordinary account endpoints should use
    /// <see cref="GenerateRecoveryCodesAsync" />.
    /// </remarks>
    Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesPrivilegedAsync(Guid userId, RecoveryCodeGenerationRequest? request = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all existing recovery codes for the specified user.
    /// </summary>
    /// <param name="userId">User whose recovery codes should be revoked.</param>
    /// <param name="request">Fresh MFA proof, optional reason, tenant scope, and audit context for the revocation operation.</param>
    /// <param name="cancellationToken">Token for aborting revocation work.</param>
    /// <returns>Number of recovery-code credentials revoked.</returns>
    Task<int> RevokeRecoveryCodesAsync(Guid userId, RevokeRecoveryCodesRequest? request = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all recovery codes through an explicitly privileged recovery or administration path.
    /// </summary>
    /// <param name="userId">User whose recovery codes should be revoked.</param>
    /// <param name="request">Optional reason, tenant scope, and audit context for the revocation operation.</param>
    /// <param name="cancellationToken">Token for aborting revocation work.</param>
    /// <returns>Number of recovery-code credentials revoked.</returns>
    Task<int> RevokeRecoveryCodesPrivilegedAsync(Guid userId, RevokeRecoveryCodesRequest? request = null, CancellationToken cancellationToken = default);
}
