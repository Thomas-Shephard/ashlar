namespace Ashlar.Identity.Models;

/// <summary>
/// Request to verify one factor in an MFA handshake.
/// </summary>
/// <param name="HandshakeToken">The raw handshake token returned when MFA was required.</param>
/// <param name="FactorType">The factor being verified.</param>
/// <param name="Metadata">Optional metadata captured with the factor verification.</param>
public sealed record VerifyAuthenticationHandshakeRequest(
    string HandshakeToken,
    string FactorType,
    IDictionary<string, string>? Metadata = null);
