namespace Ashlar.Identity.Models;

public sealed record AuthenticationHandshakeResult(
    bool Succeeded,
    AuthenticationHandshake? Handshake = null,
    string? ErrorMessage = null);
