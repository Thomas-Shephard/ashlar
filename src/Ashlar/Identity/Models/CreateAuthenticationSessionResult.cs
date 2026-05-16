namespace Ashlar.Identity.Models;

/// <summary>
/// Result returned when an authentication <paramref name="Session" /> is created.
/// </summary>
/// <param name="Token">The token value.</param>
/// <param name="Session">The session value.</param>
public sealed record CreateAuthenticationSessionResult(string Token, AuthenticationSession Session);
