namespace Ashlar.Authorization.Models;

/// <summary>Security services required by app-facing authorization grant mutations.</summary>
/// <param name="Authorizer">Host policy for grant mutation operations.</param>
/// <param name="SessionRepository">Storage used to confirm the actor's session remains active.</param>
public sealed record AuthorizationGrantMutationContext(
    IAccountSecurityOperationAuthorizer? Authorizer = null,
    IAuthenticationSessionRepository? SessionRepository = null);
