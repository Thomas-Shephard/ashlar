namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Describes the outcome of authentication session validation.
/// </summary>
public enum AuthenticationSessionValidationStatus
{
    /// <summary>
    /// The token was missing, malformed, or did not match an active session. Avoid exposing the precise reason to untrusted clients.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// The token matched an active, unexpired, unrevoked session.
    /// </summary>
    Succeeded = 1,
    /// <summary>
    /// The token matched a session whose lifetime has elapsed.
    /// </summary>
    Expired = 2,
    /// <summary>
    /// The token matched a session that was explicitly revoked.
    /// </summary>
    Revoked = 3
}
