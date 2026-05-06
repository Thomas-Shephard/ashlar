namespace Ashlar.Identity.Models;

public sealed record VerifyAuthenticationHandshakeRequest(
    string HandshakeToken,
    string FactorType,
    IDictionary<string, string>? Metadata = null);
