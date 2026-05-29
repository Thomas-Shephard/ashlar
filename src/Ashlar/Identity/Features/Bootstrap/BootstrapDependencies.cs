using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Features.Bootstrap;

/// <summary>
/// Groups bootstrap service dependencies to simplify service construction.
/// </summary>
/// <param name="storeContext">Bootstrap persistence dependencies.</param>
/// <param name="tokenContext">Token hashing dependencies.</param>
/// <param name="infrastructure">Rate limiting dependencies.</param>
/// <param name="audit">Audit and notification dependencies.</param>
/// <param name="grantService">Optional authorization grant service for bootstrap grant assignment.</param>
internal sealed class BootstrapDependencies(
    BootstrapStoreContext storeContext,
    SecureTokenContext tokenContext,
    IdentityInfrastructureContext infrastructure,
    IdentityAuditContext audit,
    IAuthorizationGrantService? grantService = null)
{
    private readonly BootstrapStoreContext _storeContext = storeContext ?? throw new ArgumentNullException(nameof(storeContext));
    private readonly SecureTokenContext _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
    private readonly IdentityInfrastructureContext _infrastructure = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    private readonly IdentityAuditContext _audit = audit ?? throw new ArgumentNullException(nameof(audit));

    /// <summary>
    /// Gets the bootstrap state repository.
    /// </summary>
    public IBootstrapStateRepository StateRepository => _storeContext.StateRepository;
    /// <summary>
    /// Gets the user repository.
    /// </summary>
    public IUserRepository UserRepository => _storeContext.UserRepository;
    /// <summary>
    /// Gets the transaction provider.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider => _storeContext.TransactionProvider;
    /// <summary>
    /// Gets the secure token context.
    /// </summary>
    public SecureTokenContext TokenContext => _tokenContext;
    /// <summary>
    /// Gets the authentication rate limiter.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter => _infrastructure.RateLimiter;
    /// <summary>
    /// Gets the time provider.
    /// </summary>
    public TimeProvider TimeProvider => _audit.TimeProvider;
    /// <summary>
    /// Gets the security event sink.
    /// </summary>
    public ISecurityEventSink SecurityEventSink => _audit.SecurityEventSink;
    /// <summary>
    /// Gets the security notification service.
    /// </summary>
    public ISecurityNotificationService? NotificationService => _audit.NotificationService;
    /// <summary>
    /// Gets the optional authorization grant service.
    /// </summary>
    public IAuthorizationGrantService? GrantService { get; } = grantService;
}
