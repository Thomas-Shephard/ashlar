using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Features.Email;

/// <summary>
/// Groups dependencies used by email change flows.
/// </summary>
/// <param name="identityContext">Identity repositories and transaction dependencies.</param>
/// <param name="tokenContext">Token generator and hasher dependencies.</param>
/// <param name="infrastructure">Messaging, rate limiting, and URI validation dependencies.</param>
/// <param name="sessionRepository">Session storage used to revoke sessions after email changes.</param>
/// <param name="secretProtector">Protector used for payloads that must remain confidential at rest.</param>
/// <param name="audit">Audit and notification dependencies.</param>
internal sealed class EmailChangeDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IAuthenticationSessionRepository sessionRepository,
    ISecretProtector secretProtector,
    IdentityAuditContext audit)
{
    /// <summary>
    /// Gets identity repositories and transaction dependencies.
    /// </summary>
    public IdentityContext IdentityContext { get; } = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    /// <summary>
    /// Gets token generator and hasher dependencies.
    /// </summary>
    public SecureTokenContext TokenContext { get; } = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    /// <summary>
    /// Gets messaging, rate limiting, and URI validation dependencies.
    /// </summary>
    public IdentityInfrastructureContext Infrastructure { get; } = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    /// <summary>
    /// Gets session storage used to revoke sessions after email changes.
    /// </summary>
    public IAuthenticationSessionRepository SessionRepository { get; } = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
    /// <summary>
    /// Gets the protector used for confidential email-change payloads.
    /// </summary>
    public ISecretProtector SecretProtector { get; } = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
    /// <summary>
    /// Gets audit and notification dependencies.
    /// </summary>
    public IdentityAuditContext Audit { get; } = audit ?? throw new ArgumentNullException(nameof(audit));
    /// <summary>
    /// Gets the optional security notification service.
    /// </summary>
    public ISecurityNotificationService? NotificationService => Audit.NotificationService;
    /// <summary>
    /// Gets the clock used for timestamps.
    /// </summary>
    public TimeProvider TimeProvider => Audit.TimeProvider;
    /// <summary>
    /// Gets the sink used to record security events.
    /// </summary>
    public ISecurityEventSink SecurityEventSink => Audit.SecurityEventSink;
    /// <summary>
    /// Gets the email sender used for change confirmation messages.
    /// </summary>
    public IEmailSender EmailSender => Infrastructure.EmailSender;
    /// <summary>
    /// Gets the rate limiter used for email change flows.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter => Infrastructure.RateLimiter;
    /// <summary>
    /// Gets the URI validator used for callback URLs.
    /// </summary>
    public IUriValidator UriValidator => Infrastructure.UriValidator;
}
