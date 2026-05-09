using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity;

public sealed class EmailChangeDependencies(
    IdentityContext identityContext,
    SecureTokenContext tokenContext,
    IEmailSender emailSender,
    IAuthenticationRateLimiter rateLimiter,
    IAuthenticationSessionRepository sessionRepository,
    ISecretProtector secretProtector,
    EmailChangeAuditDependencies audit)
{
    public IdentityContext IdentityContext { get; } = identityContext ?? throw new ArgumentNullException(nameof(identityContext));
    public SecureTokenContext TokenContext { get; } = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    public IEmailSender EmailSender { get; } = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    public IAuthenticationSessionRepository SessionRepository { get; } = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
    public ISecretProtector SecretProtector { get; } = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
    public EmailChangeAuditDependencies Audit { get; } = audit ?? throw new ArgumentNullException(nameof(audit));
    public TimeProvider TimeProvider => Audit.TimeProvider;
    public ISecurityEventSink SecurityEventSink => Audit.SecurityEventSink;
}

public sealed class EmailChangeAuditDependencies(
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink)
{
    public TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    public ISecurityEventSink SecurityEventSink { get; } = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
}
