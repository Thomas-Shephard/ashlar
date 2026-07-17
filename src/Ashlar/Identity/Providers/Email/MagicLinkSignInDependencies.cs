using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Groups the dependencies used when issuing and consuming magic links.
/// </summary>
/// <param name="identityContext">Identity user, credential, service, and transaction dependencies.</param>
/// <param name="tokenContext">Secure token generation and hashing dependencies.</param>
/// <param name="infrastructure">Email, rate-limit, and callback validation dependencies.</param>
/// <param name="provider">Authentication provider that owns issued magic-link credentials.</param>
/// <param name="authenticationOrchestrator">Completes sign-in through MFA-aware orchestration.</param>
/// <param name="audit">Time and security-event dependencies.</param>
internal sealed class MagicLinkSignInDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    MagicLinkAuthenticationProvider provider,
    IAuthenticationOrchestrator authenticationOrchestrator,
    IdentityAuditContext audit)
{
    private readonly IdentityContext _identityContext = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    private readonly SecureTokenContext _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    private readonly IdentityInfrastructureContext _infrastructure = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    private readonly IdentityAuditContext _audit = audit ?? throw new ArgumentNullException(nameof(audit));

    /// <summary>
    /// Gets the user repository used for email lookup.
    /// </summary>
    public IUserRepository UserRepository => _identityContext.UserRepository;
    /// <summary>
    /// Gets the credential repository used for magic-link credentials.
    /// </summary>
    public ICredentialRepository CredentialRepository => _identityContext.CredentialRepository;
    /// <summary>
    /// Gets the transaction provider used to persist magic-link issuance atomically.
    /// </summary>
    public AshlarDurableTransactionProvider TransactionProvider => _identityContext.TransactionProvider;
    /// <summary>
    /// Gets the generator used to create magic-link tokens.
    /// </summary>
    public ISecureTokenGenerator TokenGenerator => _tokenContext.Generator;
    /// <summary>
    /// Gets the hasher used to store magic-link token hashes.
    /// </summary>
    public ISecureTokenHasher TokenHasher => _tokenContext.Hasher;
    /// <summary>
    /// Gets the authentication provider that owns issued magic-link credentials.
    /// </summary>
    public MagicLinkAuthenticationProvider Provider { get; } = provider ?? throw new ArgumentNullException(nameof(provider));
    /// <summary>
    /// Gets the orchestrator used to complete sign-in while enforcing MFA policy.
    /// </summary>
    public IAuthenticationOrchestrator AuthenticationOrchestrator { get; } = authenticationOrchestrator ?? throw new ArgumentNullException(nameof(authenticationOrchestrator));
    /// <summary>
    /// Gets the sender used for magic-link messages.
    /// </summary>
    public IEmailSender EmailSender => _infrastructure.EmailSender;
    /// <summary>
    /// Gets the limiter used to throttle magic-link requests.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter => _infrastructure.RateLimiter;
    /// <summary>
    /// Gets the validator used for callback URIs.
    /// </summary>
    public IUriValidator UriValidator => _infrastructure.UriValidator;
    /// <summary>
    /// Gets the time provider used for expiration checks and events.
    /// </summary>
    public TimeProvider TimeProvider => _audit.TimeProvider;
    /// <summary>
    /// Gets the sink used to record security events.
    /// </summary>
    public ISecurityEventSink SecurityEventSink => _audit.SecurityEventSink;
}
