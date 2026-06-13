namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides administrator-oriented account security operations.
/// </summary>
/// <remarks>
/// These operations do not authorize callers. Host applications must enforce administrator authorization and fresh MFA
/// or equivalent step-up policy before calling destructive account-security operations.
/// </remarks>
public interface IAccountSecurityService
{
    /// <summary>
    /// Changes a user's account state.
    /// </summary>
    /// <param name="userId">The user to update.</param>
    /// <param name="request">Explicit mutation scope, audit metadata, target state, and revocation behavior.</param>
    /// <param name="cancellationToken">A token that can cancel the account-state update.</param>
    /// <returns>The updated account-state details or an operation failure.</returns>
    Task<Result<AccountSecurityOperationResult>> SetUserAccountStateAsync(Guid userId, SetUserAccountStateRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active authentication sessions for a user.
    /// </summary>
    /// <param name="userId">The user whose sessions should be revoked.</param>
    /// <param name="request">Audit, tenant, and reason metadata for the operation.</param>
    /// <param name="cancellationToken">A token that can cancel session revocation.</param>
    /// <returns>The number of sessions revoked and any operation failure.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active credentials for a user matching the provider key.
    /// </summary>
    /// <param name="userId">The user whose credentials should be revoked.</param>
    /// <param name="provider">The credential provider to revoke.</param>
    /// <param name="request">Audit, tenant, and reason metadata for the operation.</param>
    /// <param name="cancellationToken">A token that can cancel credential revocation.</param>
    /// <returns>The number of credentials revoked and any operation failure.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes TOTP credentials, recovery-code credentials, and remembered MFA devices for a user.
    /// </summary>
    /// <param name="userId">The user whose MFA material should be reset.</param>
    /// <param name="request">Audit, tenant, and reason metadata for the operation.</param>
    /// <param name="cancellationToken">A token that can cancel MFA reset work.</param>
    /// <returns>The number of MFA artifacts revoked and any operation failure.</returns>
    Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns a non-secret account-security posture summary for a user account.
    /// </summary>
    /// <param name="userId">The user account whose posture should be returned.</param>
    /// <param name="request">Tenant scope and recent-event window options for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel posture lookup.</param>
    /// <returns>The non-secret posture summary or a lookup failure.</returns>
    Task<Result<AccountSecurityPosture>> GetUserSecurityPostureAsync(Guid userId, AccountSecurityPostureRequest? request = null, CancellationToken cancellationToken = default);
}
