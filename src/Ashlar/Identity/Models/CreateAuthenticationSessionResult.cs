namespace Ashlar.Identity.Models;

/// <summary>
/// Result returned when an authentication session is created.
/// </summary>
/// <param name="Token">The raw session token. This is only returned at creation time.</param>
/// <param name="Session">The persisted session metadata containing only the token hash.</param>
public sealed record CreateAuthenticationSessionResult(string Token, AuthenticationSession Session);
