namespace Ashlar.Identity.Models;

/// <summary>
/// Represents the verify authentication handshake request data model.
/// </summary>
/// <param name="HandshakeToken">The handshake token value.</param>
/// <param name="FactorType">The factor type value.</param>
/// <param name="Metadata">The metadata value.</param>
public sealed record VerifyAuthenticationHandshakeRequest(
    string HandshakeToken,
    string FactorType,
    IDictionary<string, string>? Metadata = null);
