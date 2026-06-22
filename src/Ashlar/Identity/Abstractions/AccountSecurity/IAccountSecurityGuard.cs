namespace Ashlar.Identity.Abstractions.AccountSecurity;

/// <summary>
/// Allows applications to veto high-risk administrator account security operations before Ashlar persists them.
/// </summary>
/// <remarks>
/// Hosts remain responsible for deciding whether account-state changes require business approval, risk review,
/// tenant-specific policy, or separation-of-duties checks. <see cref="AllowAccountSecurityGuard"/> is the default
/// low-friction implementation and intentionally approves every operation.
/// </remarks>
public interface IAccountSecurityGuard
{
    /// <summary>
    /// Determines whether a user's account state can be changed to <paramref name="targetState"/>.
    /// </summary>
    /// <param name="user">The user whose account state would change.</param>
    /// <param name="targetState">State the caller wants to apply to the account.</param>
    /// <param name="request">Audit metadata and optional tenant scope.</param>
    /// <param name="cancellationToken">A token that can cancel guard evaluation.</param>
    /// <returns>The guard decision.</returns>
    Task<Result> CanChangeAccountStateAsync(IUser user, UserAccountState targetState, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Permissive account security guard that approves every account-state change.
/// </summary>
/// <remarks>
/// This implementation is registered by default by <c>AddAshlarIdentity</c> so new applications can start without
/// writing policy code. Replace it with an application-specific <see cref="IAccountSecurityGuard"/> before relying on
/// account-state changes for business approval, risk review, or separation-of-duties controls.
/// </remarks>
public sealed class AllowAccountSecurityGuard : IAccountSecurityGuard
{
    /// <inheritdoc />
    public Task<Result> CanChangeAccountStateAsync(IUser user, UserAccountState targetState, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult(Result.Success());
    }
}
