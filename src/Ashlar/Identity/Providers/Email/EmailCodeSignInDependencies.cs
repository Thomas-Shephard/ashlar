using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;

namespace Ashlar.Identity.Providers.Email;

public sealed class EmailCodeSignInDependencies(
    IdentityContext identityContext,
    IEmailSender emailSender,
    IAuthenticationRateLimiter rateLimiter,
    EmailCodeAuthenticationProvider provider,
    ISecurityEventSink? securityEventSink = null,
    TimeProvider? timeProvider = null)
{
    private readonly IdentityContext _identityContext = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    public IIdentityRepository Repository => _identityContext.Repository;
    public IIdentityService IdentityService => _identityContext.IdentityService;
    public IAshlarTransactionProvider TransactionProvider => _identityContext.TransactionProvider;
    public IEmailSender EmailSender { get; } = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    public EmailCodeAuthenticationProvider Provider { get; } = provider ?? throw new ArgumentNullException(nameof(provider));
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;
}
