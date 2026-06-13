using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Features.Email;

/// <summary>
/// Provides shared email-flow rate-limit helpers.
/// </summary>
internal static class EmailFlowRateLimitHelpers
{
    /// <summary>
    /// Converts an audit context into authentication context metadata for rate-limit keys.
    /// </summary>
    /// <param name="audit">The optional audit context.</param>
    /// <returns>Metadata copied from the authentication context for rate-limit attempts.</returns>
    public static AuthenticationContext? ToAuthenticationContext(AuditContext? audit)
    {
        return audit == null
            ? null
            : new AuthenticationContext { IpAddress = audit.IpAddress, CorrelationId = audit.CorrelationId };
    }

    /// <summary>
    /// Checks a layered email verification rate-limit bucket.
    /// </summary>
    /// <param name="rateLimitChecker">The rate-limit checker.</param>
    /// <param name="purpose">The verification purpose.</param>
    /// <param name="key">The safe dimension key.</param>
    /// <param name="userId">The user being verified.</param>
    /// <param name="context">Authentication context metadata used to populate rate-limit attempt fields.</param>
    /// <param name="rule">The rate-limit rule.</param>
    /// <param name="cancellationToken">A token that can cancel the check.</param>
    /// <returns>The rate-limit decision.</returns>
    public static Task<RateLimitDecision> CheckVerificationRateLimitAsync(
        AuthenticationRateLimitChecker rateLimitChecker,
        string purpose,
        string key,
        Guid userId,
        AuthenticationContext? context,
        RateLimitRule rule,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rateLimitChecker);
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        return rateLimitChecker.CheckAsync(
            new AuthenticationRateLimitCheck(purpose, AuthenticationRateLimitDimensions.DimensionName(key), key, rule)
            {
                UserId = userId,
                Context = context
            },
            cancellationToken);
    }
}

/// <summary>
/// Checks verification rate limits for a configured email flow purpose.
/// </summary>
/// <param name="rateLimitChecker">The rate-limit checker.</param>
/// <param name="purpose">The verification purpose.</param>
internal sealed class EmailFlowVerificationRateLimitChecker(AuthenticationRateLimitChecker rateLimitChecker, string purpose)
{
    private readonly AuthenticationRateLimitChecker _rateLimitChecker = rateLimitChecker;
    private readonly string _purpose = purpose;

    /// <summary>
    /// Checks a verification rate-limit bucket.
    /// </summary>
    /// <param name="key">The safe dimension key.</param>
    /// <param name="userId">The user being verified.</param>
    /// <param name="context">Authentication context metadata used to populate rate-limit attempt fields.</param>
    /// <param name="rule">The rate-limit rule.</param>
    /// <param name="cancellationToken">A token that can cancel the check.</param>
    /// <returns>The rate-limit decision.</returns>
    public Task<RateLimitDecision> CheckAsync(
        string key,
        Guid userId,
        AuthenticationContext? context,
        RateLimitRule rule,
        CancellationToken cancellationToken)
    {
        return EmailFlowRateLimitHelpers.CheckVerificationRateLimitAsync(
            _rateLimitChecker,
            _purpose,
            key,
            userId,
            context,
            rule,
            cancellationToken);
    }
}
