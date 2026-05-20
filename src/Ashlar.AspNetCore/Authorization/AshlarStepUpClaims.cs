using System.Globalization;
using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;

namespace Ashlar.AspNetCore.Authorization;

internal static class AshlarStepUpClaims
{
    public static AuthenticationSession? ToSession(ClaimsPrincipal user)
    {
        if (!TryGetGuid(user, AshlarClaimTypes.SessionId, out var sessionId) ||
            !TryGetGuid(user, ClaimTypes.NameIdentifier, out var userId))
        {
            return null;
        }

        var session = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TokenHash = "not-exposed-to-claims",
            CreatedAt = DateTimeOffset.UnixEpoch,
            ExpiresAt = DateTimeOffset.MaxValue
        };

        if (!TrySetOptionalTime(user, AshlarClaimTypes.AuthenticatedAt, value => session.AuthenticatedAt = value) ||
            !TrySetOptionalTime(user, AshlarClaimTypes.AdditionalVerificationAt, value => session.AdditionalVerificationAt = value))
        {
            return null;
        }

        if (!TrySetOptionalProvider(user, AshlarClaimTypes.PrimaryProviderType, AshlarClaimTypes.PrimaryProviderName, value => session.PrimaryProvider = value) ||
            !TrySetOptionalProvider(user, AshlarClaimTypes.AdditionalVerificationProviderType, AshlarClaimTypes.AdditionalVerificationProviderName, value => session.AdditionalVerificationProvider = value))
        {
            return null;
        }

        session.AdditionalVerificationFactor = user.FindFirst(AshlarClaimTypes.AdditionalVerificationFactor)?.Value;
        return session;
    }

    private static bool TryGetGuid(ClaimsPrincipal user, string claimType, out Guid value)
    {
        return Guid.TryParse(user.FindFirst(claimType)?.Value, out value);
    }

    private static bool TrySetOptionalTime(ClaimsPrincipal user, string claimType, Action<DateTimeOffset> setValue)
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

        try
        {
            setValue(DateTimeOffset.FromUnixTimeSeconds(seconds));
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static bool TrySetOptionalProvider(
        ClaimsPrincipal user,
        string typeClaim,
        string nameClaim,
        Action<AuthenticationProviderKey> setValue)
    {
        var type = user.FindFirst(typeClaim)?.Value;
        var name = user.FindFirst(nameClaim)?.Value;
        if (string.IsNullOrWhiteSpace(type) && string.IsNullOrWhiteSpace(name))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        setValue(new AuthenticationProviderKey(type, name));
        return true;
    }
}


