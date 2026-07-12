namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Reads automatic account-lockout state without enabling resets.</summary>
public interface IAccountLockoutAdministrationReader
{
    /// <summary>Searches automatic account-lockout state.</summary>
    /// <param name="request">Tenant scope, filters, and paging limits.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Matching lockout rows and paging metadata.</returns>
    Task<Result<AccountLockoutSearchResult>> SearchLockoutsAsync(SearchAccountLockoutsRequest request, CancellationToken cancellationToken = default);

    /// <summary>Gets automatic lockout status for a user and provider.</summary>
    /// <param name="userId">User whose lockout status should be returned.</param>
    /// <param name="provider">Authentication provider key.</param>
    /// <param name="request">Explicit tenant scope for the lookup.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>Current lockout status.</returns>
    Task<Result<AccountLockoutStatus>> GetLockoutStatusAsync(Guid userId, AuthenticationProviderKey provider, AccountLockoutStatusRequest request, CancellationToken cancellationToken = default);
}
