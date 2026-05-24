using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Features.Invitations;

/// <summary>
/// Groups invitation service dependencies to simplify service construction.
/// </summary>
/// <param name="storeContext">The store context value.</param>
/// <param name="tokenContext">The token context value.</param>
/// <param name="infrastructure">The infrastructure value.</param>
/// <param name="audit">The audit value.</param>
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
    /// Gets or sets the invitation repository value.
    /// </summary>
    public IInvitationRepository InvitationRepository => _storeContext.InvitationRepository;
    /// <summary>
    /// Gets or sets the user repository value.
    /// </summary>
    public IUserRepository UserRepository => _storeContext.UserRepository;
    /// <summary>
    /// Gets or sets the transaction provider value.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider => _storeContext.TransactionProvider;
    /// <summary>
    /// Gets or sets the token generator value.
    /// </summary>
    public ISecureTokenGenerator TokenGenerator => _tokenContext.Generator;
    /// <summary>
    /// Gets or sets the token hasher value.
    /// </summary>
    public ISecureTokenHasher TokenHasher => _tokenContext.Hasher;
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
    public ISecurityEventSink? SecurityEventSink => _audit.SecurityEventSink;
    /// <summary>
    /// Gets or sets the notification service value.
    /// </summary>
    public ISecurityNotificationService? NotificationService => _audit.NotificationService;
}
