namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Result returned after validating a presented bearer token.
/// </summary>
/// <param name="Succeeded">Whether validation produced an active <paramref name="Session" />.</param>
/// <param name="Session">The matching <paramref name="Session" /> when validation succeeds.</param>
/// <param name="UserId">The owner of the matching record, when known.</param>
/// <param name="Status">Validation outcome. Avoid exposing precise failure status to untrusted clients.</param>
public sealed record ValidateAuthenticationSessionResult(
    bool Succeeded,
    AuthenticationSession? Session,
    Guid? UserId,
    AuthenticationSessionValidationStatus Status)
{
    /// <summary>
    /// A generic failed validation result with no matching session.
    /// </summary>
    public static ValidateAuthenticationSessionResult Failed { get; } =
        new(false, null, null, AuthenticationSessionValidationStatus.Failed);
}
