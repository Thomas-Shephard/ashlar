namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Request to begin verification for an MFA handshake before resolving the concrete factor to complete.
/// </summary>
/// <param name="HandshakeToken">The raw handshake token returned when MFA or step-up verification was required. Do not log or persist this value.</param>
/// <param name="Context">Authentication request context used for audit and rate limiting.</param>
public sealed record BeginAuthenticationHandshakeVerificationRequest(
    string? HandshakeToken,
    AuthenticationContext? Context = null);
