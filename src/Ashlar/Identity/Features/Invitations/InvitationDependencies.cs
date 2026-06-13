using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Features.Invitations;

/// <summary>
/// Groups invitation service dependencies to simplify service construction.
/// </summary>
/// <param name="storeContext">Invitation storage and transaction dependencies.</param>
/// <param name="tokenContext">Token generator and hasher dependencies.</param>
/// <param name="infrastructure">Messaging, rate limiting, and URI validation dependencies.</param>
/// <param name="audit">Audit and notification dependencies.</param>
internal sealed class InvitationDependencies(
    InvitationStoreContext storeContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IdentityAuditContext audit)
{
    private readonly InvitationStoreContext _storeContext = storeContext ?? throw new ArgumentNullException(nameof(storeContext));
    private readonly SecureTokenContext _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    private readonly IdentityInfrastructureContext _infrastructure = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    private readonly IdentityAuditContext _audit = audit ?? throw new ArgumentNullException(nameof(audit));

    /// <summary>
    /// Gets invitation storage.
    /// </summary>
    public IInvitationRepository InvitationRepository => _storeContext.InvitationRepository;
    /// <summary>
    /// Gets user storage used when accepting invitations.
    /// </summary>
    public IUserRepository UserRepository => _storeContext.UserRepository;
    /// <summary>
    /// Gets the transaction provider used for invitation mutations.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider => _storeContext.TransactionProvider;
    /// <summary>
    /// Gets the generator used for raw invitation tokens.
    /// </summary>
    public ISecureTokenGenerator TokenGenerator => _tokenContext.Generator;
    /// <summary>
    /// Gets the hasher used before persisting invitation tokens.
    /// </summary>
    public ISecureTokenHasher TokenHasher => _tokenContext.Hasher;
    /// <summary>
    /// Gets the email sender used for invitation messages.
    /// </summary>
    public IEmailSender EmailSender => _infrastructure.EmailSender;
    /// <summary>
    /// Gets the rate limiter used for invitation flows.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter => _infrastructure.RateLimiter;
    /// <summary>
    /// Gets the URI validator used for invitation callback URLs.
    /// </summary>
    public IUriValidator UriValidator => _infrastructure.UriValidator;
    /// <summary>
    /// Gets the clock used for timestamps.
    /// </summary>
    public TimeProvider TimeProvider => _audit.TimeProvider;
    /// <summary>
    /// Gets the optional sink used to record invitation security events.
    /// </summary>
    public ISecurityEventSink? SecurityEventSink => _audit.SecurityEventSink;
    /// <summary>
    /// Gets the optional security notification service.
    /// </summary>
    public ISecurityNotificationService? NotificationService => _audit.NotificationService;
}
