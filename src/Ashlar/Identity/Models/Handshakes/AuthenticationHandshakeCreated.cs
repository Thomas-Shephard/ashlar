namespace Ashlar.Identity.Models.Handshakes;

/// <summary>
/// Represents the authentication <paramref name="Handshake" /> created data model.
/// </summary>
/// <param name="Handshake">The handshake value.</param>
/// <param name="Token">The token value.</param>
public record AuthenticationHandshakeCreated(AuthenticationHandshake Handshake, string Token);





