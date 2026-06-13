namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Result returned after creating an MFA or step-up challenge.
/// </summary>
/// <param name="Handshake">The persisted challenge record. It contains a storage-safe hash, not bearer material.</param>
/// <param name="Token">The raw bearer value for the created challenge. Return it to the client once; do not log or persist this value.</param>
public record AuthenticationHandshakeCreated(AuthenticationHandshake Handshake, string Token);
