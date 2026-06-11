namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides administrator-oriented account security operations.
/// </summary>
public interface IAccountSecurityService
{
    /// <summary>
    /// Changes a user's account state.
    /// </summary>
    /// <param name="userId">The user to update.</param>
    /// <param name="request">The account-state transition request.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The account-state transition result.</returns>
    Task<Result<AccountSecurityOperationResult>> SetUserAccountStateAsync(Guid userId, SetUserAccountStateRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active authentication sessions for a user.
    /// </summary>
    /// <param name="userId">The user whose sessions should be revoked.</param>
    /// <param name="request">Audit, tenant, and reason metadata for the operation.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active credentials for a user matching the provider key.
    /// </summary>
    /// <param name="userId">The user whose credentials should be revoked.</param>
    /// <param name="provider">The credential provider to revoke.</param>
    /// <param name="request">Audit, tenant, and reason metadata for the operation.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes TOTP credentials, recovery-code credentials, and remembered MFA devices for a user.
    /// </summary>
    /// <param name="userId">The user whose MFA material should be reset.</param>
    /// <param name="request">Audit, tenant, and reason metadata for the operation.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns a non-secret account-security posture summary for a user account.
    /// </summary>
    /// <param name="userId">The user account whose posture should be returned.</param>
    /// <param name="request">Tenant scope and recent-event window options for the lookup.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AccountSecurityPosture>> GetUserSecurityPostureAsync(Guid userId, AccountSecurityPostureRequest? request = null, CancellationToken cancellationToken = default);
}
