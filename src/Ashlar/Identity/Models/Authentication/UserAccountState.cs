namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Defines provider-neutral user account states.
/// </summary>
public enum UserAccountState
{
    /// <summary>
    /// The account can sign in.
    /// </summary>
    Active = 0,

    /// <summary>
    /// The account was administratively disabled.
    /// </summary>
    Disabled = 1,

    /// <summary>
    /// The account is locked.
    /// </summary>
    Locked = 2,

    /// <summary>
    /// The account is suspended.
    /// </summary>
    Suspended = 3
}

/// <summary>
/// Provides helpers for <see cref="UserAccountState" />.
/// </summary>
public static class UserAccountStates
{
    /// <summary>
    /// Gets whether the account state permits sign-in.
    /// </summary>
    /// <param name="state">The account state value.</param>
    /// <returns><see langword="true" /> when sign-in can proceed.</returns>
    public static bool CanSignIn(this UserAccountState state)
    {
        return state == UserAccountState.Active;
    }

    /// <summary>
    /// Gets the stable provider storage value.
    /// </summary>
    /// <param name="state">The account state value.</param>
    /// <returns>The stable storage value.</returns>
    public static string ToStorageValue(this UserAccountState state)
    {
        return state switch
        {
            UserAccountState.Active => "active",
            UserAccountState.Disabled => "disabled",
            UserAccountState.Locked => "locked",
            UserAccountState.Suspended => "suspended",
            _ => throw new ArgumentOutOfRangeException(nameof(state), state, "Unknown user account state.")
        };
    }

    /// <summary>
    /// Parses a stable provider storage value.
    /// </summary>
    /// <param name="value">The storage value.</param>
    /// <returns>The account state.</returns>
    public static UserAccountState FromStorageValue(string value)
    {
        return value switch
        {
            "active" => UserAccountState.Active,
            "disabled" => UserAccountState.Disabled,
            "locked" => UserAccountState.Locked,
            "suspended" => UserAccountState.Suspended,
            _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown user account state.")
        };
    }

    /// <summary>
    /// Gets whether the user can sign in based on account state.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <returns><see langword="true" /> when sign-in can proceed.</returns>
    public static bool CanSignIn(this IUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        return user.AccountState.CanSignIn();
    }

    /// <summary>
    /// Gets the safe security-event failure reason for an account state.
    /// </summary>
    /// <param name="state">The account state value.</param>
    /// <returns>The safe failure reason value.</returns>
    public static string ToSecurityFailureReason(this UserAccountState state)
    {
        return state switch
        {
            UserAccountState.Active => throw new InvalidOperationException("Active accounts do not have a sign-in failure reason."),
            UserAccountState.Disabled => Auditing.SecurityEventFailureReasons.UserDisabled,
            UserAccountState.Locked => Auditing.SecurityEventFailureReasons.UserLocked,
            UserAccountState.Suspended => Auditing.SecurityEventFailureReasons.UserSuspended,
            _ => Auditing.SecurityEventFailureReasons.InvalidCredentials
        };
    }
}
