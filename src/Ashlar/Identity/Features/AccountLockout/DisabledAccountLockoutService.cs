namespace Ashlar.Identity.Features.AccountLockout;

internal sealed class DisabledAccountLockoutService : IAccountLockoutService
{
    public static DisabledAccountLockoutService Instance { get; } = new();

    private DisabledAccountLockoutService()
    {
    }

    public Task<AccountLockoutStatus> GetStatusAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(CreateStatus(user, provider));
    }

    public Task<AccountLockoutFailureResult> RecordFailureAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new AccountLockoutFailureResult(CreateStatus(user, provider), false, false));
    }

    public Task<bool> ResetAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = CreateStatus(user, provider);
        return Task.FromResult(false);
    }

    private static AccountLockoutStatus CreateStatus(IUser user, AuthenticationProviderKey provider)
    {
        ArgumentNullException.ThrowIfNull(user);
        AuthenticationProviderKey.ThrowIfNotConfigured(provider, nameof(provider));

        var tenantId = (user as ITenantUser)?.TenantId;
        return AccountLockoutStatus.None(user.Id, tenantId, provider);
    }
}
