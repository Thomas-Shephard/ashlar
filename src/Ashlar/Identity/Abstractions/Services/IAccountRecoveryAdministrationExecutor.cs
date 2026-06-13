namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Executes destructive administrator account recovery operations after host applications have authorized the caller.
/// </summary>
/// <remarks>
/// This service intentionally does not authorize callers or perform step-up checks. Host applications must protect usage with
/// administrator authorization, fresh MFA or equivalent step-up policy, and their own approval workflow before calling these methods.
/// Use <see cref="IAccountRecoveryAdministrationService" /> for read-only recovery option previews.
/// </remarks>
public interface IAccountRecoveryAdministrationExecutor
{
    /// <summary>
    /// Revokes TOTP credentials, recovery-code credentials, and remembered MFA devices for a user.
    /// </summary>
    /// <param name="request">Target user, explicit scope, required audit metadata, and display-safe reason for the destructive MFA reset.</param>
    /// <param name="cancellationToken">A token that can cancel destructive MFA reset work.</param>
    /// <returns>The operation counts and stable failure information.</returns>
    Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(
        AccountRecoveryResetMfaRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active authentication sessions for a user.
    /// </summary>
    /// <param name="request">Target user, explicit scope, required audit metadata, and display-safe reason for destructive session revocation.</param>
    /// <param name="cancellationToken">A token that can cancel destructive session revocation.</param>
    /// <returns>The operation counts and stable failure information.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(
        AccountRecoveryRevokeSessionsRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active credentials for a user matching the requested provider key.
    /// </summary>
    /// <param name="request">Target user, provider key, explicit scope, required audit metadata, and display-safe reason for destructive credential revocation.</param>
    /// <param name="cancellationToken">A token that can cancel destructive credential revocation.</param>
    /// <returns>The operation counts and stable failure information.</returns>
    Task<Result<AccountSecurityOperationResult>> RevokeProviderCredentialsAsync(
        AccountRecoveryRevokeProviderCredentialsRequest request,
        CancellationToken cancellationToken = default);
}
