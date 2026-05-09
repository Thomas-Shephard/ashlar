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
    IEmailSender emailSender,
    IAuthenticationRateLimiter rateLimiter,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink = null,
    ISecurityNotificationService? notificationService = null)
{
    private readonly InvitationStoreContext _storeContext = storeContext ?? throw new ArgumentNullException(nameof(storeContext));
    private readonly SecureTokenContext _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    public IInvitationRepository InvitationRepository => _storeContext.InvitationRepository;
    public IIdentityRepository IdentityRepository => _storeContext.IdentityRepository;
    public IAshlarTransactionProvider TransactionProvider => _storeContext.TransactionProvider;
    public ISecureTokenGenerator TokenGenerator => _tokenContext.Generator;
    public ISecureTokenHasher TokenHasher => _tokenContext.Hasher;
    public IEmailSender EmailSender { get; } = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    public TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
