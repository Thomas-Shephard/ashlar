namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Performs destructive account-security operations after validating actor context, fresh proof, its active source session, and host authorization.
/// Fresh proofs are rejected when their source session is missing, expired, or revoked.
/// </summary>
public interface IAccountSecurityAdministrationService
{
    /// <summary>Changes the target user's account state.</summary>
    /// <param name="request">The actor-bound, authorized account-state request.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The account-security mutation result.</returns>
    Task<Result<AccountSecurityOperationResult>> SetUserAccountStateAsync(SetUserAccountStateAdministrationRequest request, CancellationToken cancellationToken = default);

    /// <summary>Revokes active sessions for the target user.</summary>
    /// <param name="request">The actor-bound, authorized session-revocation request.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The account-security mutation result.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(AccountSecurityAdministrationRequest request, CancellationToken cancellationToken = default);

    /// <summary>Revokes credentials for one provider from the target user.</summary>
    /// <param name="request">The actor-bound, authorized credential-revocation request.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The account-security mutation result.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(RevokeAccountCredentialsRequest request, CancellationToken cancellationToken = default);

    /// <summary>Revokes the target user's MFA credentials and remembered devices.</summary>
    /// <param name="request">The actor-bound, authorized MFA-reset request.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The account-security mutation result.</returns>
    Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(AccountSecurityAdministrationRequest request, CancellationToken cancellationToken = default);

    /// <summary>Revokes one remembered MFA device.</summary>
    /// <param name="request">The actor-bound remembered-device request.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The account-security mutation result.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDeviceAsync(RevokeRememberedMfaDeviceAdministrationRequest request, CancellationToken cancellationToken = default);

    /// <summary>Revokes remembered MFA devices for the target user.</summary>
    /// <param name="request">The actor-bound remembered-device request.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The account-security mutation result.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDevicesAsync(AccountSecurityAdministrationRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Authorizes an authenticated actor to perform a specific account-security operation and scope.
/// </summary>
public interface IAccountSecurityOperationAuthorizer
{
    /// <summary>Evaluates the actor, operation, target, and requested target scope.</summary>
    /// <param name="context">The validated authorization context.</param>
    /// <param name="cancellationToken">A token that can cancel authorization.</param>
    /// <returns><see langword="true" /> only when the host authorizes the complete operation and scope.</returns>
    ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default);
}
