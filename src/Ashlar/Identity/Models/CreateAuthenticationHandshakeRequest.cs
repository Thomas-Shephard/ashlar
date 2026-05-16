namespace Ashlar.Identity.Models;

/// <summary>
/// Represents the create authentication handshake request data model.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="RequiredFactors">The required factors value.</param>
/// <param name="Metadata">The metadata value.</param>
/// <param name="Context">The authentication request context value.</param>
public sealed record CreateAuthenticationHandshakeRequest(
    Guid UserId,
    IEnumerable<string> RequiredFactors,
    IDictionary<string, string>? Metadata = null,
    AuthenticationContext? Context = null);
