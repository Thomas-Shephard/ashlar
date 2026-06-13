namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Manages automatic account lockout state for resolved users.
/// </summary>
public interface IAccountLockoutService
{
    /// <summary>
    /// Reads automatic lockout status for the resolved user and authentication provider.
    /// </summary>
    /// <param name="user">The resolved user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="context">Optional tenant and audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel lockout status lookup.</param>
    /// <returns>Current automatic lockout status for the user/provider pair.</returns>
    Task<AccountLockoutStatus> GetStatusAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a failed credential verification for a resolved user and provider.
    /// </summary>
    /// <param name="user">The resolved user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="context">Optional tenant and audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel failure recording.</param>
    /// <returns>The updated failure and lockout state.</returns>
    Task<AccountLockoutFailureResult> RecordFailureAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears automatic lockout failures for a resolved user and provider after successful authentication.
    /// </summary>
    /// <param name="user">The resolved user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="context">Optional tenant and audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel lockout reset.</param>
    /// <returns><see langword="true" /> when stored automatic lockout state was cleared.</returns>
    Task<bool> ResetAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default);
}
