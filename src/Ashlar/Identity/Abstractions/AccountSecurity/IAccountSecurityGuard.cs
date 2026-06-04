namespace Ashlar.Identity.Abstractions.AccountSecurity;

/// <summary>
/// Allows applications to veto high-risk administrator account security operations.
/// </summary>
public interface IAccountSecurityGuard
{
    /// <summary>
    /// Determines whether a user's account state can be changed.
    /// </summary>
    /// <param name="user">The user whose account state would change.</param>
    /// <param name="targetState">The requested account state.</param>
    /// <param name="request">Audit metadata and optional tenant scope.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The guard decision.</returns>
    Task<Result> CanChangeAccountStateAsync(IUser user, UserAccountState targetState, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Allows all account security operations.
/// </summary>
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
