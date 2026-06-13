namespace Ashlar.Identity.Abstractions.Tenancy;

/// <summary>
/// Describes the account fields Ashlar needs from a host user record.
/// </summary>
public interface IUser
{
    /// <summary>
    /// Stable user identifier.
    /// </summary>
    Guid Id { get; }
    /// <summary>
    /// Normalized email address used for account lookup and notifications.
    /// </summary>
    string Email { get; }
    /// <summary>
    /// Optional display name supplied by the host application.
    /// </summary>
    string? Name { get; }
    /// <summary>
    /// Account state that controls whether authentication can continue.
    /// </summary>
    UserAccountState AccountState { get; }
    /// <summary>
    /// UTC time when the email address was verified, when known.
    /// </summary>
    DateTimeOffset? EmailVerifiedAt { get; }
}
