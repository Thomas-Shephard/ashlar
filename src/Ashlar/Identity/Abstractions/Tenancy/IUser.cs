namespace Ashlar.Identity.Abstractions.Tenancy;

/// <summary>
/// Defines the contract for iuser operations.
/// </summary>
public interface IUser
{
    /// <summary>
    /// Gets the id value.
    /// </summary>
    Guid Id { get; }
    /// <summary>
    /// Gets the email value.
    /// </summary>
    string Email { get; }
    /// <summary>
    /// Gets the name value.
    /// </summary>
    string? Name { get; }
    /// <summary>
    /// Gets the account state value.
    /// </summary>
    UserAccountState AccountState { get; }
    /// <summary>
    /// Gets the email verified at value.
    /// </summary>
    DateTimeOffset? EmailVerifiedAt { get; }
}
