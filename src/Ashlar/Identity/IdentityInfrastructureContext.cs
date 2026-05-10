using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;

namespace Ashlar.Identity;

/// <summary>
/// Groups infrastructure-related dependencies like emailing and rate limiting.
/// </summary>
public sealed class IdentityInfrastructureContext(
    IEmailSender emailSender,
    IAuthenticationRateLimiter rateLimiter,
    IUriValidator uriValidator)
{
    public IEmailSender EmailSender { get; } = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    public IUriValidator UriValidator { get; } = uriValidator ?? throw new ArgumentNullException(nameof(uriValidator));
}
