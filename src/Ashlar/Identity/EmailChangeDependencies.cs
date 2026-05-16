using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity;

/// <summary>
/// Provides email change dependencies behavior.
/// </summary>
/// <param name="identityContext">The identity context value.</param>
/// <param name="tokenContext">The token context value.</param>
/// <param name="infrastructure">The infrastructure value.</param>
/// <param name="sessionRepository">The session repository value.</param>
/// <param name="secretProtector">The secret protector value.</param>
/// <param name="audit">The audit value.</param>
public sealed class EmailChangeDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IAuthenticationSessionRepository sessionRepository,
    ISecretProtector secretProtector,
    IdentityAuditContext audit)
{
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IdentityContext IdentityContext { get; } = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public SecureTokenContext TokenContext { get; } = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IdentityInfrastructureContext Infrastructure { get; } = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IAuthenticationSessionRepository SessionRepository { get; } = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public ISecretProtector SecretProtector { get; } = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IdentityAuditContext Audit { get; } = audit ?? throw new ArgumentNullException(nameof(audit));
    /// <summary>
    /// Gets or sets the notification service value.
    /// </summary>
    public ISecurityNotificationService? NotificationService => Audit.NotificationService;
    /// <summary>
    /// Gets or sets the time provider value.
    /// </summary>
    public TimeProvider TimeProvider => Audit.TimeProvider;
    /// <summary>
    /// Gets or sets the security event sink value.
    /// </summary>
    public ISecurityEventSink SecurityEventSink => Audit.SecurityEventSink;
    /// <summary>
    /// Gets or sets the email sender value.
    /// </summary>
    public IEmailSender EmailSender => Infrastructure.EmailSender;
    /// <summary>
    /// Gets or sets the rate limiter value.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter => Infrastructure.RateLimiter;
    /// <summary>
    /// Gets or sets the uri validator value.
    /// </summary>
    public IUriValidator UriValidator => Infrastructure.UriValidator;
}
