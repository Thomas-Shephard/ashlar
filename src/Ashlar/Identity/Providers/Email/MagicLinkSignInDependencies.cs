using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

public sealed class MagicLinkSignInDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    MagicLinkAuthenticationProvider provider,
    IdentityAuditContext audit)
{
    private readonly IdentityContext _identityContext = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    private readonly SecureTokenContext _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    private readonly IdentityInfrastructureContext _infrastructure = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    private readonly IdentityAuditContext _audit = audit ?? throw new ArgumentNullException(nameof(audit));

    public IIdentityService IdentityService => _identityContext.IdentityService;
    public IIdentityRepository Repository => _identityContext.Repository;
    public IAshlarTransactionProvider TransactionProvider => _identityContext.TransactionProvider;
    public ISecureTokenGenerator TokenGenerator => _tokenContext.Generator;
    public ISecureTokenHasher TokenHasher => _tokenContext.Hasher;
    public MagicLinkAuthenticationProvider Provider { get; } = provider ?? throw new ArgumentNullException(nameof(provider));
    public IEmailSender EmailSender => _infrastructure.EmailSender;
    public IAuthenticationRateLimiter RateLimiter => _infrastructure.RateLimiter;
    public IUriValidator UriValidator => _infrastructure.UriValidator;
    public TimeProvider TimeProvider => _audit.TimeProvider;
    public ISecurityEventSink SecurityEventSink => _audit.SecurityEventSink;
}
