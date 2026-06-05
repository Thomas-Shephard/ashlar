namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides administrator-oriented automatic account lockout visibility and reset operations.
/// </summary>
/// <remarks>
/// These operations do not authorize callers. Host applications must protect usage with appropriate admin authorization and step-up policy.
/// Returned models contain only safe operational metadata and never include credential values, secrets, token material, or repository versions.
/// </remarks>
public interface IAccountLockoutAdministrationService
{
    /// <summary>
    /// Searches automatic account lockout state for administrator and operations interfaces.
    /// </summary>
    /// <param name="request">The search request.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The paged lockout search result.</returns>
    Task<Result<AccountLockoutSearchResult>> SearchLockoutsAsync(SearchAccountLockoutsRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets current automatic lockout status for a user and provider in an explicit tenant scope.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="request">The tenant-scoped request.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The current lockout status, or an unlocked empty status when no failure state is stored.</returns>
    Task<Result<AccountLockoutStatus>> GetLockoutStatusAsync(
        Guid userId,
        AuthenticationProviderKey provider,
        AccountLockoutAdministrationRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears stored automatic lockout failures for a user and provider in an explicit tenant scope.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="request">The tenant-scoped request.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns><see langword="true" /> when stored automatic lockout state was cleared.</returns>
    Task<Result<bool>> ResetLockoutAsync(
        Guid userId,
        AuthenticationProviderKey provider,
        ResetAccountLockoutRequest request,
        CancellationToken cancellationToken = default);
}
