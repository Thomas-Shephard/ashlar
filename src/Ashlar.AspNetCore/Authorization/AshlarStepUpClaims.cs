using System.Globalization;
using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;

namespace Ashlar.AspNetCore.Authorization;

internal static class AshlarStepUpClaims
{
    public static bool MatchesSession(ClaimsPrincipal user, AuthenticationSession session)
    {
        if (!ClaimMatches(user, AshlarClaimTypes.SessionId, session.Id))
        {
            return false;
        }

        if (!ClaimMatches(user, ClaimTypes.NameIdentifier, session.UserId))
        {
            return false;
        }

        if (!OptionalClaimMatches(user, AshlarClaimTypes.TenantId, session.TenantId))
        {
            return false;
        }

        if (!OptionalClaimMatches(user, AshlarClaimTypes.AuthenticatedAt, session.AuthenticatedAt))
        {
            return false;
        }

        if (!OptionalClaimMatches(user, AshlarClaimTypes.AdditionalVerificationAt, session.AdditionalVerificationAt))
        {
            return false;
        }

        if (!OptionalProviderClaimsMatch(user, AshlarClaimTypes.PrimaryProviderType, AshlarClaimTypes.PrimaryProviderName, session.PrimaryProvider))
        {
            return false;
        }

        if (!OptionalProviderClaimsMatch(user, AshlarClaimTypes.AdditionalVerificationProviderType, AshlarClaimTypes.AdditionalVerificationProviderName, session.AdditionalVerificationProvider))
        {
            return false;
        }

        var factorClaim = user.FindFirst(AshlarClaimTypes.AdditionalVerificationFactor)?.Value;
        if (string.IsNullOrWhiteSpace(factorClaim))
        {
            return true;
        }

        return string.Equals(factorClaim, session.AdditionalVerificationFactor, StringComparison.Ordinal);
    }

    private static bool ClaimMatches(ClaimsPrincipal user, string claimType, Guid expected)
    {
        if (!Guid.TryParse(user.FindFirst(claimType)?.Value, out var actual))
        {
            return false;
        }

        return actual == expected;
    }

    private static bool OptionalClaimMatches(ClaimsPrincipal user, string claimType, Guid? expected)
    {
        var claimValue = user.FindFirst(claimType)?.Value;
        if (string.IsNullOrWhiteSpace(claimValue))
        {
            return true;
        }

        if (!Guid.TryParse(claimValue, out var actual))
        {
            return false;
        }

        return expected == actual;
    }

    private static bool OptionalClaimMatches(ClaimsPrincipal user, string claimType, DateTimeOffset? expected)
    {
        var claimValue = user.FindFirst(claimType)?.Value;
        if (string.IsNullOrWhiteSpace(claimValue))
        {
            return true;
        }

        if (!long.TryParse(claimValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
        {
            return false;
        }

        if (!IsUnixTimeSecondsInRange(seconds))
        {
            return false;
        }

        return expected.HasValue && expected.Value.ToUnixTimeSeconds() == seconds;
    }

    private static bool OptionalProviderClaimsMatch(
        ClaimsPrincipal user,
        string typeClaim,
        string nameClaim,
        AuthenticationProviderKey? expected)
    {
        var type = user.FindFirst(typeClaim)?.Value;
        var name = user.FindFirst(nameClaim)?.Value;
        if (string.IsNullOrWhiteSpace(type))
        {
            return string.IsNullOrWhiteSpace(name);
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        return expected == new AuthenticationProviderKey(type, name);
    }

    private static bool IsUnixTimeSecondsInRange(long seconds)
    {
        return seconds >= DateTimeOffset.MinValue.ToUnixTimeSeconds() &&
            seconds <= DateTimeOffset.MaxValue.ToUnixTimeSeconds();
    }
}
