using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Provides magic link sign in dependencies behavior.
/// </summary>
/// <param name="identityContext">The identity context value.</param>
/// <param name="tokenContext">The token context value.</param>
/// <param name="infrastructure">The infrastructure value.</param>
/// <param name="provider">The provider value.</param>
/// <param name="audit">The audit value.</param>
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

    /// <summary>
    /// Gets or sets the identity service value.
    /// </summary>
    public IIdentityService IdentityService => _identityContext.IdentityService;
    /// <summary>
    /// Gets or sets the repository value.
    /// </summary>
    public IIdentityRepository Repository => _identityContext.Repository;
    /// <summary>
    /// Gets or sets the transaction provider value.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider => _identityContext.TransactionProvider;
    /// <summary>
    /// Gets or sets the token generator value.
    /// </summary>
    public ISecureTokenGenerator TokenGenerator => _tokenContext.Generator;
    /// <summary>
    /// Gets or sets the token hasher value.
    /// </summary>
    public ISecureTokenHasher TokenHasher => _tokenContext.Hasher;
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public MagicLinkAuthenticationProvider Provider { get; } = provider ?? throw new ArgumentNullException(nameof(provider));
    /// <summary>
    /// Gets or sets the email sender value.
    /// </summary>
    public IEmailSender EmailSender => _infrastructure.EmailSender;
    /// <summary>
    /// Gets or sets the rate limiter value.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter => _infrastructure.RateLimiter;
    /// <summary>
    /// Gets or sets the uri validator value.
    /// </summary>
    public IUriValidator UriValidator => _infrastructure.UriValidator;
    /// <summary>
    /// Gets or sets the time provider value.
    /// </summary>
    public TimeProvider TimeProvider => _audit.TimeProvider;
    /// <summary>
    /// Gets or sets the security event sink value.
    /// </summary>
    public ISecurityEventSink SecurityEventSink => _audit.SecurityEventSink;
}
