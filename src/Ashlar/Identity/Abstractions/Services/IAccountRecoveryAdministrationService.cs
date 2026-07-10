namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator account recovery option summaries.
/// </summary>
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
