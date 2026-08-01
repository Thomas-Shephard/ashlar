namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Reads automatic account-lockout state without enabling resets.</summary>
public interface IAccountLockoutAdministrationReader
{
    /// <summary>Searches automatic account-lockout state.</summary>
    /// <param name="actor">Authenticated administrator context.</param>
    /// <param name="request">Tenant scope, filters, and paging limits.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Matching lockout rows and paging metadata.</returns>
    Task<Result<AccountLockoutSearchResult>> SearchLockoutsAsync(AccountSecurityActorContext actor, SearchAccountLockoutsRequest request, CancellationToken cancellationToken = default);

    /// <summary>Gets automatic lockout status for a user and provider.</summary>
    /// <param name="actor">Authenticated administrator context.</param>
    /// <param name="request">Target user, authentication provider, and explicit tenant scope.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>Current lockout status.</returns>
    Task<Result<AccountLockoutStatus>> GetLockoutStatusAsync(AccountSecurityActorContext actor, AccountLockoutStatusRequest request, CancellationToken cancellationToken = default);
}
