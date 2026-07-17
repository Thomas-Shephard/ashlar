using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Groups the dependencies used when issuing and verifying email sign-in codes.
/// </summary>
/// <param name="identityContext">Identity user, credential, service, and transaction dependencies.</param>
/// <param name="emailSender">Sends email-code messages.</param>
/// <param name="rateLimiter">Applies request and verification rate limits.</param>
/// <param name="provider">Authentication provider that owns the generated credentials.</param>
/// <param name="authenticationOrchestrator">Completes sign-in through MFA-aware orchestration.</param>
/// <param name="timeProvider">Supplies the current time for expiration checks.</param>
/// <param name="securityEventSink">Optional sink for security events.</param>
internal sealed class EmailCodeSignInDependencies(
    IdentityContext identityContext,
    IEmailSender emailSender,
    IAuthenticationRateLimiter rateLimiter,
    EmailCodeAuthenticationProvider provider,
    IAuthenticationOrchestrator authenticationOrchestrator,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null)
{
    private readonly IdentityContext _identityContext = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    /// <summary>
    /// Gets the user repository used for email lookup.
    /// </summary>
    public IUserRepository UserRepository => _identityContext.UserRepository;
    /// <summary>
    /// Gets the credential repository used for email-code credentials.
    /// </summary>
    public ICredentialRepository CredentialRepository => _identityContext.CredentialRepository;
    /// <summary>
    /// Gets the transaction provider used to persist code issuance atomically.
    /// </summary>
    public AshlarDurableTransactionProvider TransactionProvider => _identityContext.TransactionProvider;
    /// <summary>
    /// Gets the sender used for email-code messages.
    /// </summary>
    public IEmailSender EmailSender { get; } = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    /// <summary>
    /// Gets the limiter used to throttle email-code flows.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    /// <summary>
    /// Gets the authentication provider that owns issued email-code credentials.
    /// </summary>
    public EmailCodeAuthenticationProvider Provider { get; } = provider ?? throw new ArgumentNullException(nameof(provider));
    /// <summary>
    /// Gets the orchestrator used to complete sign-in while enforcing MFA policy.
    /// </summary>
    public IAuthenticationOrchestrator AuthenticationOrchestrator { get; } = authenticationOrchestrator ?? throw new ArgumentNullException(nameof(authenticationOrchestrator));
    /// <summary>
    /// Gets the time provider used for code lifetime checks.
    /// </summary>
    public TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    /// <summary>
    /// Gets the optional sink used to record security events.
    /// </summary>
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
}
