using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;

namespace Ashlar.Identity.Providers.Email;

public sealed class EmailCodeSignInDependencies(
    IIdentityRepository repository,
    IIdentityService identityService,
    IEmailSender emailSender,
    IAuthenticationRateLimiter rateLimiter,
    EmailCodeAuthenticationProvider provider,
    ISecurityEventSink? securityEventSink = null,
    TimeProvider? timeProvider = null)
{
    public IIdentityRepository Repository { get; } = repository ?? throw new ArgumentNullException(nameof(repository));
    public IIdentityService IdentityService { get; } = identityService ?? throw new ArgumentNullException(nameof(identityService));
    public IEmailSender EmailSender { get; } = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    public EmailCodeAuthenticationProvider Provider { get; } = provider ?? throw new ArgumentNullException(nameof(provider));
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;
}
