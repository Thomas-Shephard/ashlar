using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Builds provider-neutral primary authentication rate-limit keys.
/// </summary>
public static class PrimaryAuthenticationRateLimitKeyBuilder
{
    private const string Purpose = "primary-authentication";

    /// <summary>
    /// Builds the layered rate-limit attempts for a primary authentication operation.
    /// </summary>
    /// <param name="context">The authentication context.</param>
    /// <param name="assertion">The assertion being authenticated.</param>
    /// <param name="providerKey">The provider identity.</param>
    /// <returns>The layered attempts to evaluate.</returns>
    public static IReadOnlyList<RateLimitAttempt> BuildAttempts(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        AuthenticationProviderKey providerKey)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);

        var normalizedEmail = NormalizeEmail(context.Email);
        var identity = GetIdentityDimension(context, assertion, normalizedEmail);
        var source = GetSourceDimension(context);
        var sourceAttempt = CreateAttempt(context, providerKey, "source", source, normalizedEmail);
        if (string.Equals(identity, source, StringComparison.Ordinal))
        {
            return [sourceAttempt];
        }

        return
        [
            sourceAttempt,
            CreateAttempt(context, providerKey, "identity", identity, normalizedEmail)
        ];
    }

    /// <summary>
    /// Normalizes a provider selector for option lookup.
    /// </summary>
    /// <param name="providerKey">The provider identity.</param>
    /// <returns>The normalized selector.</returns>
    public static string NormalizeProviderSelector(AuthenticationProviderKey providerKey)
    {
        return AuthenticationRateLimitKeyBuilder.NormalizeProviderSelector(providerKey);
    }

    private static RateLimitAttempt CreateAttempt(
        AuthenticationContext context,
        AuthenticationProviderKey providerKey,
        string dimensionName,
        string dimensionValue,
        string? normalizedEmail)
    {
        return AuthenticationRateLimitKeyBuilder.BuildAttempt(
            Purpose,
            dimensionName,
            dimensionValue,
            context,
            providerKey,
            email: normalizedEmail);
    }

    private static string GetIdentityDimension(AuthenticationContext context, IAuthenticationAssertion assertion, string? normalizedEmail)
    {
        if (context.UserId.HasValue)
        {
            return $"user:{context.UserId.Value:D}";
        }

        if (!string.IsNullOrWhiteSpace(normalizedEmail))
        {
            return $"email:{normalizedEmail}";
        }

        if (assertion is ICredentialKeyAuthenticationAssertion credentialKeyAssertion &&
            !string.IsNullOrWhiteSpace(credentialKeyAssertion.CredentialKey))
        {
            return $"credential:{credentialKeyAssertion.CredentialKey.Trim()}";
        }

        return GetSourceDimension(context);
    }

    private static string GetSourceDimension(AuthenticationContext context)
    {
        return AuthenticationRateLimitDimensions.Source(context);
    }

    private static string? NormalizeEmail(string? email)
    {
        return string.IsNullOrWhiteSpace(email)
            ? null
            : IdentityNormalization.NormalizeEmail(email);
    }
}
