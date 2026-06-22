namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides administrator-oriented automatic account lockout visibility and reset operations.
/// </summary>
/// <remarks>
/// These operations do not authorize callers. Host applications must protect usage with appropriate admin authorization and step-up policy.
/// Returned models contain only safe operational metadata and never include credential values, secrets, token material, or repository versions.
/// Reset operations are destructive administrative operations and require host applications to enforce fresh MFA or equivalent step-up policy.
/// </remarks>
public interface IAccountLockoutAdministrationService
{
    /// <summary>
    /// Searches automatic account lockout state for administrator and operations interfaces.
    /// </summary>
    /// <param name="request">Tenant scope, filters, and paging limits for the administrator search.</param>
    /// <param name="cancellationToken">A token that can cancel lockout search.</param>
    /// <returns>The matching lockout rows and paging metadata.</returns>
    Task<Result<AccountLockoutSearchResult>> SearchLockoutsAsync(SearchAccountLockoutsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets current automatic lockout status for a user and provider in an explicit tenant scope.
    /// </summary>
    /// <param name="userId">User whose automatic lockout status should be returned.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="request">Explicit tenant scope for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel lockout lookup.</param>
    /// <returns>Current lockout status, or an unlocked empty status when no failure state is stored.</returns>
    Task<Result<AccountLockoutStatus>> GetLockoutStatusAsync(
        Guid userId,
        AuthenticationProviderKey provider,
        AccountLockoutStatusRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears stored automatic lockout failures for a user and provider in an explicit tenant scope.
    /// </summary>
    /// <param name="userId">User whose automatic lockout state should be cleared.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="request">Explicit tenant scope and required audit metadata for the reset.</param>
    /// <param name="cancellationToken">A token that can cancel lockout reset.</param>
    /// <returns>Stable reset outcome and the target scope.</returns>
    Task<Result<ResetAccountLockoutResult>> ResetLockoutAsync(
        Guid userId,
        AuthenticationProviderKey provider,
        ResetAccountLockoutRequest request,
        CancellationToken cancellationToken = default);
}
