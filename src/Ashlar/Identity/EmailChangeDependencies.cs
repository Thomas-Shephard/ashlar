using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity;

public sealed class EmailChangeDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IAuthenticationSessionRepository sessionRepository,
    ISecretProtector secretProtector,
    IdentityAuditContext audit)
{
    public IdentityContext IdentityContext { get; } = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    public SecureTokenContext TokenContext { get; } = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    public IdentityInfrastructureContext Infrastructure { get; } = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    public IAuthenticationSessionRepository SessionRepository { get; } = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
    public ISecretProtector SecretProtector { get; } = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
    public IdentityAuditContext Audit { get; } = audit ?? throw new ArgumentNullException(nameof(audit));
    public ISecurityNotificationService? NotificationService => Audit.NotificationService;
    public TimeProvider TimeProvider => Audit.TimeProvider;
    public ISecurityEventSink SecurityEventSink => Audit.SecurityEventSink;
    public IEmailSender EmailSender => Infrastructure.EmailSender;
    public IAuthenticationRateLimiter RateLimiter => Infrastructure.RateLimiter;
    public IUriValidator UriValidator => Infrastructure.UriValidator;
}
