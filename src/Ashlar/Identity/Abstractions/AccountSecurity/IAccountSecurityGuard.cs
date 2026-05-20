
namespace Ashlar.Identity.Abstractions.AccountSecurity;

/// <summary>
/// Allows applications to veto high-risk administrator account security operations.
/// </summary>
public interface IAccountSecurityGuard
{
    /// <summary>
    /// Determines whether a user can be disabled.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> CanDisableUserAsync(IUser user, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Allows all account security operations.
/// </summary>
public sealed class AllowAccountSecurityGuard : IAccountSecurityGuard
{
    /// <inheritdoc />
    public Task<Result> CanDisableUserAsync(IUser user, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult(Result.Success());
    }
}





