namespace Ashlar.Identity.Models;

/// <summary>
/// Result returned when a presented authentication session token is validated.
/// </summary>
/// <param name="Succeeded">Whether validation succeeded.</param>
/// <param name="Session">The matching session when one was found.</param>
/// <param name="UserId">The owning user identifier when validation succeeded.</param>
/// <param name="Status">The validation status.</param>
public sealed record ValidateAuthenticationSessionResult(
    bool Succeeded,
    AuthenticationSession? Session,
    Guid? UserId,
    AuthenticationSessionValidationStatus Status)
{
    public static ValidateAuthenticationSessionResult Failed { get; } =
        new(false, null, null, AuthenticationSessionValidationStatus.Failed);
}
