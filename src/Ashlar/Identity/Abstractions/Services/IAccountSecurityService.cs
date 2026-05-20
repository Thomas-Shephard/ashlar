
namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides administrator-oriented account security operations.
/// </summary>
public interface IAccountSecurityService
{
    /// <summary>
    /// Disables a user and revokes their active authentication sessions.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AccountSecurityOperationResult>> DisableUserAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reactivates a disabled user without changing credentials.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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





