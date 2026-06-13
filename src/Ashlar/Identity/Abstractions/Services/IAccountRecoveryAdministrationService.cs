namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator account recovery option summaries.
/// </summary>
/// <remarks>
/// This service is intended for administrative and operations tooling and does not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization before presenting destructive account operations.
/// Host applications must enforce fresh MFA or equivalent step-up policy before executing any destructive operation.
/// </remarks>
public interface IAccountRecoveryAdministrationService
{
    /// <summary>
    /// Gets display-safe recovery and destructive-operation options for a user account.
    /// </summary>
    /// <param name="request">The target user and tenant scope for the recovery option lookup.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>Display-safe recovery options for the requested user.</returns>
    Task<Result<AccountRecoveryOptions>> GetAccountRecoveryOptionsAsync(
        AccountRecoveryOptionsRequest request,
        CancellationToken cancellationToken = default);
}
