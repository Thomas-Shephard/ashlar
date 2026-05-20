using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;

namespace Ashlar.Identity.Features.Infrastructure;

/// <summary>
/// Groups infrastructure-related dependencies like emailing and rate limiting.
/// </summary>
/// <param name="emailSender">The email sender value.</param>
/// <param name="rateLimiter">The rate limiter value.</param>
/// <param name="uriValidator">The uri validator value.</param>
internal sealed class IdentityInfrastructureContext(
    IEmailSender emailSender,
    IAuthenticationRateLimiter rateLimiter,
    IUriValidator uriValidator)
{
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IEmailSender EmailSender { get; } = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IUriValidator UriValidator { get; } = uriValidator ?? throw new ArgumentNullException(nameof(uriValidator));
}
