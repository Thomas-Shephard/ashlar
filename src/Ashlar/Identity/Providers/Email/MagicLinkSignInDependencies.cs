using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

public sealed class MagicLinkSignInDependencies(
    IdentityContext identityContext,
    IEmailSender emailSender,
    SecureTokenContext tokenContext,
    IAuthenticationRateLimiter rateLimiter,
    MagicLinkAuthenticationProvider provider,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null)
{
    private readonly IdentityContext _identityContext = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    private readonly SecureTokenContext _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    public IIdentityService IdentityService => _identityContext.IdentityService;
    public IIdentityRepository Repository => _identityContext.Repository;
    public IAshlarTransactionProvider TransactionProvider => _identityContext.TransactionProvider;
    public IEmailSender EmailSender { get; } = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    public ISecureTokenGenerator TokenGenerator => _tokenContext.Generator;
    public ISecureTokenHasher TokenHasher => _tokenContext.Hasher;
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    public MagicLinkAuthenticationProvider Provider { get; } = provider ?? throw new ArgumentNullException(nameof(provider));
    public TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
}
