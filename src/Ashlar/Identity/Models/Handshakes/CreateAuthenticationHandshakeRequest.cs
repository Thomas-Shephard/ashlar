namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Requests creation of a short-lived handshake for pending factor verification.
/// </summary>
/// <param name="UserId">User that must complete the handshake.</param>
/// <param name="RequiredFactors">Factor types required before the handshake can complete.</param>
/// <param name="Metadata">Optional host-defined metadata. Do not include secrets or credential material.</param>
/// <param name="Context">Authentication request context used for audit and rate limiting.</param>
public sealed record CreateAuthenticationHandshakeRequest(
    Guid UserId,
    IEnumerable<string> RequiredFactors,
    IDictionary<string, string>? Metadata = null,
    AuthenticationContext? Context = null);
