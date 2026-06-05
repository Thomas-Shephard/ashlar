namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Manages automatic account lockout state for resolved users.
/// </summary>
public interface IAccountLockoutService
{
    /// <summary>
    /// Gets the current automatic lockout status for a user and provider.
    /// </summary>
    /// <param name="user">The resolved user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="context">Optional tenant and audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The current lockout status.</returns>
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
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
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
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns><see langword="true" /> when stored automatic lockout state was cleared.</returns>
    Task<bool> ResetAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default);
}
