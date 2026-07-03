namespace Ashlar.Identity.Abstractions.AccountSecurity;

/// <summary>
/// Allows applications to veto high-risk administrator account-state changes before Ashlar persists them.
/// </summary>
/// <remarks>
/// Hosts remain responsible for deciding whether account-state changes require business approval, risk review,
/// tenant-specific policy, or separation-of-duties checks. <see cref="PermissiveAccountSecurityGuard"/> intentionally
/// approves every account-state change and is reported by configuration validation.
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
/// Register this implementation only when the host deliberately allows account-state changes without business
/// approval, risk review, tenant-specific policy, or separation-of-duties checks. <c>AddAshlarIdentity</c> keeps this
/// guard as a fallback for minimal composition, and configuration validation reports it as a warning.
/// </remarks>
public sealed class PermissiveAccountSecurityGuard : IAccountSecurityGuard
{
    /// <inheritdoc />
    public Task<Result> CanChangeAccountStateAsync(IUser user, UserAccountState targetState, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult(Result.Success());
    }
}
