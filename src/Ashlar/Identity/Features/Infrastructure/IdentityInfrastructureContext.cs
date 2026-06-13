using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;

namespace Ashlar.Identity.Features.Infrastructure;

/// <summary>
/// Groups infrastructure-related dependencies like emailing and rate limiting.
/// </summary>
/// <param name="emailSender">Sender used for outbound identity emails.</param>
/// <param name="rateLimiter">Rate limiter used by identity flows.</param>
/// <param name="uriValidator">Validator used for callback and return URLs.</param>
internal sealed class IdentityInfrastructureContext(
    IEmailSender emailSender,
    IAuthenticationRateLimiter rateLimiter,
    IUriValidator uriValidator)
{
    /// <summary>
    /// Gets the sender used for outbound identity emails.
    /// </summary>
    public IEmailSender EmailSender { get; } = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    /// <summary>
    /// Gets the rate limiter used by identity flows.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    /// <summary>
    /// Gets the validator used for callback and return URLs.
    /// </summary>
    public IUriValidator UriValidator { get; } = uriValidator ?? throw new ArgumentNullException(nameof(uriValidator));
}
