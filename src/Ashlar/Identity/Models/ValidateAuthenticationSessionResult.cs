namespace Ashlar.Identity.Models;

/// <summary>
/// Result returned when a presented authentication <paramref name="Session" /> token is validated.
/// </summary>
/// <param name="Succeeded">The succeeded value.</param>
/// <param name="Session">The session value.</param>
/// <param name="UserId">The user id value.</param>
/// <param name="Status">The status value.</param>
public sealed record ValidateAuthenticationSessionResult(
    bool Succeeded,
    AuthenticationSession? Session,
    Guid? UserId,
    AuthenticationSessionValidationStatus Status)
{
    /// <summary>
    /// Gets or sets the failed value.
    /// </summary>
    public static ValidateAuthenticationSessionResult Failed { get; } =
        new(false, null, null, AuthenticationSessionValidationStatus.Failed);
}
