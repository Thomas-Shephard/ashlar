using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;

namespace Ashlar.AspNetCore.Authorization;

internal static class AshlarStepUpClaims
{
    public static bool MatchesSession(ClaimsPrincipal user, ValidatedAuthenticationSession session)
    {
        return ClaimMatches(user, AshlarClaimTypes.SessionId, session.Id)
            && ClaimMatches(user, ClaimTypes.NameIdentifier, session.UserId)
            && OptionalTenantClaimMatches(user, session.TenantId);
    }

    private static bool ClaimMatches(ClaimsPrincipal user, string claimType, Guid expected)
    {
        if (!Guid.TryParse(user.FindFirst(claimType)?.Value, out var actual))
        {
            return false;
        }

        return actual == expected;
    }

    private static bool OptionalTenantClaimMatches(ClaimsPrincipal user, Guid? expected)
    {
        var claimValue = user.FindFirst(AshlarClaimTypes.TenantId)?.Value;
        if (string.IsNullOrWhiteSpace(claimValue))
        {
            return !expected.HasValue;
        }

        if (!Guid.TryParse(claimValue, out var actual))
        {
            return false;
        }

        return expected == actual;
    }
}
