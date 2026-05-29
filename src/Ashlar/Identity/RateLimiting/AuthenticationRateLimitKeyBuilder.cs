using System.Security.Cryptography;
using System.Text;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Builds safe, stable authentication rate-limit attempts.
/// </summary>
public static class AuthenticationRateLimitKeyBuilder
{
    private const string GlobalTenant = "global";
    private const string NoProvider = "none";

    /// <summary>
    /// Builds a rate-limit attempt for the supplied bucket.
    /// </summary>
    /// <param name="check">The rate-limit bucket check.</param>
    /// <returns>The rate-limit attempt.</returns>
    public static RateLimitAttempt BuildAttempt(AuthenticationRateLimitCheck check)
    {
        ArgumentNullException.ThrowIfNull(check);

        if (string.IsNullOrWhiteSpace(check.Purpose))
        {
            throw new ArgumentException("Rate-limit purpose is required.", nameof(check));
        }

        if (string.IsNullOrWhiteSpace(check.DimensionName) || string.IsNullOrWhiteSpace(check.DimensionValue))
        {
            throw new ArgumentException("Rate-limit dimension name and value are required.", nameof(check));
        }

        return BuildAttempt(
            check.Purpose,
            check.DimensionName,
            check.DimensionValue,
            check.Context,
            check.ProviderKey,
            check.TenantId,
            check.UserId,
            check.Email);
    }

    /// <summary>
    /// Builds a rate-limit attempt for the supplied bucket.
    /// </summary>
    /// <param name="purpose">The operation purpose being limited.</param>
    /// <param name="dimensionName">The safe bucket dimension name.</param>
    /// <param name="dimensionValue">The safe bucket dimension value.</param>
    /// <param name="context">The optional authentication context.</param>
    /// <param name="providerKey">The optional provider identity.</param>
    /// <param name="tenantId">The optional normalized tenant scope override.</param>
    /// <param name="userId">The optional user identity metadata.</param>
    /// <param name="email">The optional email metadata.</param>
    /// <returns>The rate-limit attempt.</returns>
    public static RateLimitAttempt BuildAttempt(
        string purpose,
        string dimensionName,
        string dimensionValue,
        AuthenticationContext? context = null,
        AuthenticationProviderKey? providerKey = null,
        Guid? tenantId = null,
        Guid? userId = null,
        string? email = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        ArgumentException.ThrowIfNullOrWhiteSpace(dimensionName);
        ArgumentException.ThrowIfNullOrWhiteSpace(dimensionValue);

        var resolvedTenantId = tenantId ?? context?.TenantId;
        var normalizedEmail = NormalizeEmail(email ?? context?.Email);
        var resolvedUserId = userId ?? context?.UserId;
        var provider = providerKey.HasValue
            ? NormalizeProviderSelector(providerKey.Value)
            : NoProvider;

        var composedKey = ComposeKey(
            purpose.Trim(),
            provider,
            resolvedTenantId?.ToString("D") ?? GlobalTenant,
            dimensionName.Trim().ToLowerInvariant(),
            dimensionValue.Trim());

        return new RateLimitAttempt
        {
            Key = HashKey(composedKey),
            Purpose = purpose.Trim(),
            Email = normalizedEmail,
            UserId = resolvedUserId?.ToString("D"),
            IpAddress = NormalizeIpAddress(context?.IpAddress),
            CorrelationId = NormalizeOptional(context?.CorrelationId)
        };
    }

    /// <summary>
    /// Normalizes a provider selector for option lookup and key construction.
    /// </summary>
    /// <param name="providerKey">The provider identity.</param>
    /// <returns>The normalized selector.</returns>
    public static string NormalizeProviderSelector(AuthenticationProviderKey providerKey)
    {
        return $"{providerKey.TypeValueOrUnknown.Trim().ToLowerInvariant()}:{providerKey.Name.Trim().ToLowerInvariant()}";
    }

    /// <summary>
    /// Hashes a composed key before handing it to persistence-backed limiters.
    /// </summary>
    /// <param name="value">The composed key.</param>
    /// <returns>The lower-case SHA-256 hexadecimal hash.</returns>
    public static string HashKey(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string ComposeKey(params string[] segments)
    {
        var capacity = 0;
        for (var i = 0; i < segments.Length; i++)
        {
            capacity += segments[i].Length + CountDigits(segments[i].Length) + 1;
            if (i > 0)
            {
                capacity++;
            }
        }

        var builder = new StringBuilder(capacity);
        for (var i = 0; i < segments.Length; i++)
        {
            if (i > 0)
            {
                builder.Append('|');
            }

            builder.Append(segments[i].Length);
            builder.Append(':');
            builder.Append(segments[i]);
        }

        return builder.ToString();
    }

    private static int CountDigits(int value)
    {
        var digits = 1;
        while (value >= 10)
        {
            value /= 10;
            digits++;
        }

        return digits;
    }

    private static string? NormalizeEmail(string? email)
    {
        return string.IsNullOrWhiteSpace(email)
            ? null
            : IdentityNormalization.NormalizeEmail(email);
    }

    private static string? NormalizeOptional(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static string? NormalizeIpAddress(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : AuthenticationRateLimitDimensions.NormalizeIpAddress(value);
    }
}
