namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides read-only administrator account recovery option summaries.
/// </summary>
/// <remarks>
/// This service is intended for administrative and operations tooling and does not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization, audit policy,
/// and step-up requirements before presenting destructive account operations.
/// </remarks>
public interface IAccountRecoveryAdministrationService
{
    /// <summary>
    /// Gets display-safe recovery and destructive-operation options for a user account.
    /// </summary>
    /// <param name="request">The recovery options request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AccountRecoveryOptions>> GetAccountRecoveryOptionsAsync(
        AccountRecoveryOptionsRequest request,
        CancellationToken cancellationToken = default);
}
