namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Result returned after issuing application access.
/// </summary>
/// <param name="Token">The raw bearer value for the issued <paramref name="Session" />. Return it to the client once; do not log, persist, or display it.</param>
/// <param name="Session">The persisted record. Only its stored hash is storage-safe.</param>
public sealed record CreateAuthenticationSessionResult(string Token, AuthenticationSession Session);
