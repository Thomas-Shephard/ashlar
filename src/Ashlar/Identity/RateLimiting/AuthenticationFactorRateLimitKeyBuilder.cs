using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Builds provider-neutral secondary factor verification rate-limit keys.
/// </summary>
public static class AuthenticationFactorRateLimitKeyBuilder
{
    private const string Purpose = "factor-verification";

    /// <summary>
    /// Builds layered rate-limit attempts for a secondary factor verification operation.
    /// </summary>
    /// <param name="context">The authentication context.</param>
    /// <param name="providerKey">The secondary factor provider identity.</param>
    /// <returns>The layered attempts to evaluate.</returns>
    public static IReadOnlyList<RateLimitAttempt> BuildAttempts(AuthenticationContext context, AuthenticationProviderKey providerKey)
    {
        ArgumentNullException.ThrowIfNull(context);

        var source = AuthenticationRateLimitDimensions.Source(context);
        var user = context.UserId.HasValue
            ? AuthenticationRateLimitDimensions.User(context.UserId.Value)
            : source;
        var sourceAttempt = CreateAttempt(context, providerKey, "source", source);
        if (string.Equals(source, user, StringComparison.Ordinal))
        {
            return [sourceAttempt];
        }

        return
        [
            sourceAttempt,
            CreateAttempt(context, providerKey, "user", user)
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
        string dimensionValue)
    {
        return AuthenticationRateLimitKeyBuilder.BuildAttempt(
            new AuthenticationRateLimitAttemptDescriptor(Purpose, dimensionName, dimensionValue)
            {
                Context = context,
                ProviderKey = providerKey,
                UserId = context.UserId
            });
    }
}
