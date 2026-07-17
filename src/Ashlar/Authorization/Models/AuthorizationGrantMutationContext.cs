namespace Ashlar.Authorization.Models;

internal sealed record AuthorizationGrantMutationContext(
    IAccountSecurityOperationAuthorizer? Authorizer = null,
    IAuthenticationSessionRepository? SessionRepository = null);
