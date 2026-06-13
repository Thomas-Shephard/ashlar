using System.Security.Cryptography;
using System.Text;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.RateLimiting;

/// <summary>
/// Builds safe, stable authentication rate-limit buckets.
/// </summary>
public static class AuthenticationRateLimitKeyBuilder
{
    private const string GlobalTenant = "global";
    private const string NoProvider = "none";

    /// <summary>
    /// Builds a hashed rate-limit bucket for the supplied check.
    /// </summary>
    /// <param name="check">The rate-limit bucket check.</param>
    /// <returns>Safe attempt metadata containing a hashed persistence key.</returns>
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
            new AuthenticationRateLimitAttemptDescriptor(check.Purpose, check.DimensionName, check.DimensionValue)
            {
                Context = check.Context,
                ProviderKey = check.ProviderKey,
                TenantId = check.TenantId,
                UserId = check.UserId,
                Email = check.Email
            });
    }

    /// <summary>
    /// Builds a hashed rate-limit bucket from explicit dimension values.
    /// </summary>
    /// <param name="purpose">The operation purpose being limited.</param>
    /// <param name="dimensionName">Normalized dimension name used to partition rate-limit buckets.</param>
    /// <param name="dimensionValue">Safe bucket value, such as a normalized email, source, or token hash.</param>
    /// <returns>Safe attempt metadata containing a hashed persistence key.</returns>
    public static RateLimitAttempt BuildAttempt(
        string purpose,
        string dimensionName,
        string dimensionValue)
    {
        return BuildAttempt(new AuthenticationRateLimitAttemptDescriptor(purpose, dimensionName, dimensionValue));
    }

    /// <summary>
    /// Builds a hashed rate-limit bucket from a descriptor.
    /// </summary>
    /// <param name="descriptor">The rate-limit attempt descriptor.</param>
    /// <returns>Safe attempt metadata containing a hashed persistence key.</returns>
    public static RateLimitAttempt BuildAttempt(AuthenticationRateLimitAttemptDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        var purpose = descriptor.Purpose;
        var dimensionName = descriptor.DimensionName;
        var dimensionValue = descriptor.DimensionValue;
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        ArgumentException.ThrowIfNullOrWhiteSpace(dimensionName);
        ArgumentException.ThrowIfNullOrWhiteSpace(dimensionValue);

        var resolvedTenantId = descriptor.TenantId ?? descriptor.Context?.TenantId;
        var normalizedEmail = NormalizeEmail(descriptor.Email ?? descriptor.Context?.Email);
        var resolvedUserId = descriptor.UserId ?? descriptor.Context?.UserId;
        var provider = descriptor.ProviderKey.HasValue
            ? NormalizeProviderSelector(descriptor.ProviderKey.Value)
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
            IpAddress = NormalizeIpAddress(descriptor.Context?.IpAddress),
            CorrelationId = NormalizeOptional(descriptor.Context?.CorrelationId)
        };
    }

    /// <summary>
    /// Normalizes a provider selector for option lookup and key construction.
    /// </summary>
    /// <param name="providerKey">The provider identity.</param>
    /// <returns>The normalized selector.</returns>
    public static string NormalizeProviderSelector(AuthenticationProviderKey providerKey)
    {
        return $"{providerKey.TypeValueOrDefault.Trim().ToLowerInvariant()}:{providerKey.Name.Trim().ToLowerInvariant()}";
    }

    /// <summary>
    /// Hashes a composed bucket key before handing it to persistence-backed limiters.
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

/// <summary>
/// Describes a rate-limit attempt to build.
/// </summary>
/// <param name="purpose">The operation purpose being limited.</param>
/// <param name="dimensionName">Normalized dimension name used to partition rate-limit buckets.</param>
/// <param name="dimensionValue">Safe bucket value, such as a normalized email, source, or token hash.</param>
public sealed class AuthenticationRateLimitAttemptDescriptor(string purpose, string dimensionName, string dimensionValue)
{
    /// <summary>
    /// Operation purpose being limited.
    /// </summary>
    public string Purpose { get; } = purpose;

    /// <summary>
    /// Normalized dimension name used to partition rate-limit buckets.
    /// </summary>
    public string DimensionName { get; } = dimensionName;

    /// <summary>
    /// Safe bucket identifier for this dimension.
    /// </summary>
    public string DimensionValue { get; } = dimensionValue;

    /// <summary>
    /// Optional authentication context used for source, tenant, and correlation metadata.
    /// </summary>
    public AuthenticationContext? Context { get; init; }

    /// <summary>
    /// Optional provider identity for provider-scoped buckets.
    /// </summary>
    public AuthenticationProviderKey? ProviderKey { get; init; }

    /// <summary>
    /// Optional normalized tenant scope override.
    /// </summary>
    public Guid? TenantId { get; init; }

    /// <summary>
    /// Optional user identity metadata.
    /// </summary>
    public Guid? UserId { get; init; }

    /// <summary>
    /// Optional normalized email metadata for rate-limit bucketing.
    /// </summary>
    public string? Email { get; init; }
}
