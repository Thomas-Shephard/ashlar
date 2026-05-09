using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

public sealed class IdentityService(
    IIdentityRepository repository,
    IAuthenticationProviderRegistry providerRegistry,
    ICredentialService credentialService,
    IAuthenticationPipeline authenticationPipeline,
    IAshlarTransactionProvider transactionProvider,
    ISecurityEventSink? securityEventSink = null,
    TimeProvider? timeProvider = null)
    : IIdentityService
{
    private readonly IIdentityRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly ICredentialService _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly IAuthenticationPipeline _authenticationPipeline = authenticationPipeline ?? throw new ArgumentNullException(nameof(authenticationPipeline));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly SecurityEventEmitter _securityEvents = new(securityEventSink, timeProvider);

    public IdentityService(
        IIdentityRepository repository,
        IEnumerable<IAuthenticationProvider> providers,
        ICredentialService credentialService,
        IAshlarTransactionProvider transactionProvider,
        ISecurityEventSink? securityEventSink = null,
        TimeProvider? timeProvider = null)
        : this(repository, new AuthenticationProviderRegistry(providers), credentialService, transactionProvider, securityEventSink, timeProvider)
    {
    }

    public IdentityService(
        IIdentityRepository repository,
        IAuthenticationProviderRegistry providerRegistry,
        ICredentialService credentialService,
        IAshlarTransactionProvider transactionProvider,
        ISecurityEventSink? securityEventSink = null,
        TimeProvider? timeProvider = null)
        : this(repository, providerRegistry, credentialService, new AuthenticationPipeline(providerRegistry, credentialService, transactionProvider, securityEventSink, timeProvider), transactionProvider, securityEventSink, timeProvider)
    {
    }

    public IEnumerable<AuthenticationProviderKey> SupportedProviderKeys => _providerRegistry.SupportedProviderKeys;

    public async Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        return await _repository.GetUserByEmailAsync(email, tenantId, cancellationToken);
    }

    public async Task<IUser?> FindByProviderKeyAsync(AuthenticationProviderKey provider, string providerKey, CancellationToken cancellationToken = default)
    {
        if (provider.Type == default || string.IsNullOrWhiteSpace(provider.Name))
        {
            throw new ArgumentException("Provider key must be fully initialized with a type and name.", nameof(provider));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);

        return await _repository.GetUserByProviderKeyAsync(provider.Type, provider.Name, providerKey, cancellationToken);
    }

    public async Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default)
    {
        return await _authenticationPipeline.LoginAsync(context, assertion, cancellationToken);
    }

    public async Task<IUser> CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        var sanitizedUser = SanitizeUserEmail(user);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        
        await _repository.CreateUserAsync(sanitizedUser, cancellationToken);
        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.UserCreated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = sanitizedUser.Id
        }, ct));

        await transaction.CommitAsync(cancellationToken);
        
        return sanitizedUser;
    }

    public async Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_providerRegistry.TryGetProvider(assertion, out var provider))
        {
            throw new ArgumentException($"Provider '{assertion.ProviderIdentity}' is not supported.", nameof(assertion));
        }

        await _credentialService.LinkCredentialAsync(userId, assertion, provider, credentialValue, cancellationToken: cancellationToken);
    }

    private static IUser SanitizeUserEmail(IUser user)
    {
        var email = IdentityNormalization.SanitizeEmailForDelivery(user.Email);
        return string.Equals(email, user.Email, StringComparison.Ordinal)
            ? user
            : new SanitizedUserWrapper(user, email);
    }

    private sealed class SanitizedUserWrapper(IUser original, string email) : ITenantUser, IHasAuditMetadata
    {
        public Guid Id => original.Id;
        public string Email { get; } = email;
        public string? Name => original.Name;
        public bool IsActive => original.IsActive;
        public Guid? TenantId => (original as ITenantUser)?.TenantId;
        public DateTimeOffset? EmailVerifiedAt => original.EmailVerifiedAt;
        public DateTimeOffset CreatedAt => (original as IHasAuditMetadata)?.CreatedAt ?? default;
        public DateTimeOffset? UpdatedAt
        {
            get => (original as IHasAuditMetadata)?.UpdatedAt;
            set
            {
                if (original is IHasAuditMetadata metadata)
                {
                    metadata.UpdatedAt = value;
                }
            }
        }
    }
}
