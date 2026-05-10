using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity;

/// <summary>
/// Groups invitation service dependencies to simplify service construction.
/// </summary>
public sealed class InvitationDependencies(
    InvitationStoreContext storeContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IdentityAuditContext audit)
{
    private readonly InvitationStoreContext _storeContext = storeContext ?? throw new ArgumentNullException(nameof(storeContext));
    private readonly SecureTokenContext _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    private readonly IdentityInfrastructureContext _infrastructure = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    private readonly IdentityAuditContext _audit = audit ?? throw new ArgumentNullException(nameof(audit));

    public IInvitationRepository InvitationRepository => _storeContext.InvitationRepository;
    public IIdentityRepository IdentityRepository => _storeContext.IdentityRepository;
    public IAshlarTransactionProvider TransactionProvider => _storeContext.TransactionProvider;
    public ISecureTokenGenerator TokenGenerator => _tokenContext.Generator;
    public ISecureTokenHasher TokenHasher => _tokenContext.Hasher;
    public IEmailSender EmailSender => _infrastructure.EmailSender;
    public IAuthenticationRateLimiter RateLimiter => _infrastructure.RateLimiter;
    public IUriValidator UriValidator => _infrastructure.UriValidator;
    public TimeProvider TimeProvider => _audit.TimeProvider;
    public ISecurityEventSink? SecurityEventSink => _audit.SecurityEventSink;
    public ISecurityNotificationService? NotificationService => _audit.NotificationService;
}
