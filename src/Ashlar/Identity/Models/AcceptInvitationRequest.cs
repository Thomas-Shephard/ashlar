namespace Ashlar.Identity.Models;

/// <summary>
/// Provides accept invitation request behavior.
/// </summary>
public sealed class AcceptInvitationRequest
{
    /// <summary>
    /// Gets or sets the token value.
    /// </summary>
    public required string Token { get; init; }
    /// <summary>
    /// Gets or sets the user name value.
    /// </summary>
    public string? UserName { get; init; }
}
