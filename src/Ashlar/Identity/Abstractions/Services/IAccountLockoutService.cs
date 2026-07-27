namespace Ashlar.Identity.Abstractions.Services;

internal interface IAccountLockoutService
{
    Task<AccountLockoutStatus> GetStatusAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default);

    Task<AccountLockoutFailureResult> RecordFailureAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default);

    Task<bool> ResetAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default);
}
