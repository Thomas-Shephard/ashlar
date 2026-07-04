namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Result returned after creating an MFA or step-up challenge.
/// </summary>
/// <param name="Handshake">Public challenge details for the created <paramref name="Token" />. Hashes are not exposed in creation results.</param>
/// <param name="Token">The raw bearer value for the created challenge. Return it to the client once; do not log or persist this value.</param>
public sealed record AuthenticationHandshakeCreated(CreatedAuthenticationHandshake Handshake, string Token);
