namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Request to verify one factor in an MFA handshake.
/// </summary>
/// <param name="HandshakeToken">The raw handshake token returned when MFA or step-up verification was required. Do not log or persist this value.</param>
/// <param name="FactorType">The factor being verified.</param>
/// <param name="Metadata">Optional metadata captured with factor verification. Do not include secrets or credential material.</param>
/// <param name="Context">Authentication request context used for audit and rate limiting.</param>
public sealed record VerifyAuthenticationHandshakeRequest(
    string? HandshakeToken,
    string FactorType,
    IDictionary<string, string>? Metadata = null,
    AuthenticationContext? Context = null);
