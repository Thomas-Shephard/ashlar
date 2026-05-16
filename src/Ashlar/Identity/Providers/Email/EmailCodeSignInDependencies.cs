using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Provides email code sign in dependencies behavior.
/// </summary>
/// <param name="identityContext">The identity context value.</param>
/// <param name="emailSender">The email sender value.</param>
/// <param name="rateLimiter">The rate limiter value.</param>
/// <param name="provider">The provider value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="securityEventSink">The security event sink value.</param>
public sealed class EmailCodeSignInDependencies(
    IdentityContext identityContext,
    IEmailSender emailSender,
    IAuthenticationRateLimiter rateLimiter,
    EmailCodeAuthenticationProvider provider,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null)
{
    private readonly IdentityContext _identityContext = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    /// <summary>
    /// Gets or sets the repository value.
    /// </summary>
    public IIdentityRepository Repository => _identityContext.Repository;
    /// <summary>
    /// Gets or sets the identity service value.
    /// </summary>
    public IIdentityService IdentityService => _identityContext.IdentityService;
    /// <summary>
    /// Gets or sets the transaction provider value.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider => _identityContext.TransactionProvider;
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
    public EmailCodeAuthenticationProvider Provider { get; } = provider ?? throw new ArgumentNullException(nameof(provider));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    /// <summary>
    /// Gets or sets the security event sink value.
    /// </summary>
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
}
