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
    /// Disables a user through the generic account-state transition flow.
    /// </summary>
    /// <param name="userId">The user to disable.</param>
    /// <param name="request">Audit metadata and optional tenant scope.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The account-state transition result.</returns>
    Task<Result<AccountSecurityOperationResult>> DisableUserAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reactivates a user through the generic account-state transition flow.
    /// </summary>
    /// <param name="userId">The user to reactivate.</param>
    /// <param name="request">Audit metadata and optional tenant scope.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The account-state transition result.</returns>
    Task<Result<AccountSecurityOperationResult>> ReactivateUserAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active authentication sessions for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active credentials for a user matching the provider key.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="provider">The provider value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes TOTP and recovery-code credentials for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns a non-secret security posture summary for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<UserSecurityPosture>> GetUserSecurityPostureAsync(Guid userId, UserSecurityPostureRequest? request = null, CancellationToken cancellationToken = default);
}
