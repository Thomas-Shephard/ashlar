using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;

namespace Ashlar.Sample.AspNetCore;

internal sealed class SampleAccountSecurityOperationAuthorizer(IAuthorizationEvaluator authorization)
    : IAccountSecurityOperationAuthorizer
{
    public async ValueTask<bool> AuthorizeAsync(
        AccountSecurityAuthorizationContext context,
        CancellationToken cancellationToken = default)
    {
        if (context.IncludeAllTenants || context.TargetTenant != context.ActorTenant)
        {
            return false;
        }

        if (context.Operation == AccountSecurityOperation.RevokeCredentials
            && context.ActorUserId == context.TargetUserId
            && context.Provider is { Type: var type }
            && (type == ProviderType.OAuth || type == ProviderType.Oidc))
        {
            return true;
        }

        if (context.ActorUserId == context.TargetUserId
            && context.Operation is AccountSecurityOperation.RevokeOwnSession
                or AccountSecurityOperation.RevokeOwnOtherSessions
                or AccountSecurityOperation.StartTotpEnrollment
                or AccountSecurityOperation.CompleteTotpEnrollment
                or AccountSecurityOperation.DisableTotp
                or AccountSecurityOperation.RevokeRememberedMfaDevice
                or AccountSecurityOperation.RevokeRememberedMfaDevices
                or AccountSecurityOperation.GenerateRecoveryCodes
                or AccountSecurityOperation.RevokeRecoveryCodes)
        {
            return true;
        }

        var result = await authorization.EvaluateAsync(
            new AuthorizationEvaluationRequest(
                context.ActorUserId,
                Role: "admin",
                TenantId: context.ActorTenant.TenantId),
            cancellationToken);
        return result.Succeeded;
    }
}
