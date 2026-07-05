using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Services;

internal sealed class IdentityService(
    IUserRepository repository,
    IAuthenticationProviderRegistry providerRegistry,
    ICredentialService credentialService,
    IAuthenticationPipeline authenticationPipeline,
    IAshlarTransactionProvider transactionProvider,
    IdentityServiceDependencies? dependencies = null)
    : IIdentityService
{
    private readonly IUserRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly ICredentialService _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly IAuthenticationPipeline _authenticationPipeline = authenticationPipeline ?? throw new ArgumentNullException(nameof(authenticationPipeline));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly SecurityEventEmitter _securityEvents = new(dependencies?.SecurityEventSink, dependencies?.TimeProvider);

    public IEnumerable<AuthenticationProviderKey> SupportedProviderKeys => _providerRegistry.SupportedProviderKeys;

    public async Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        return await _repository.GetUserByEmailAsync(email, tenantId, cancellationToken);
    }

    public async Task<IUser?> FindByProviderKeyAsync(AuthenticationProviderKey provider, string providerKey, CancellationToken cancellationToken = default)
    {
        AuthenticationProviderKey.ThrowIfNotConfigured(provider, nameof(provider));
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
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.UserCreated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = sanitizedUser.Id
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return sanitizedUser;
    }

    public async Task<Result> LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_providerRegistry.TryGetProvider(assertion, out var provider))
        {
            return Result.Failure(AshlarFailureCodes.ProviderUnsupported, $"Provider '{assertion.ProviderIdentity}' is not supported.");
        }

        return await _credentialService.LinkCredentialAsync(userId, assertion, provider, credentialValue, cancellationToken: cancellationToken);
    }

    private static IUser SanitizeUserEmail(IUser user)
    {
        var displayEmail = IdentityNormalization.SanitizeEmailForDelivery(user.DisplayEmail);
        return string.Equals(displayEmail, user.DisplayEmail, StringComparison.Ordinal)
            ? user
            : new SanitizedUserWrapper(user, displayEmail);
    }

    private sealed class SanitizedUserWrapper(IUser original, string displayEmail) : ITenantUser, IHasAuditMetadata
    {
        public Guid Id => original.Id;
        public string DisplayEmail { get; } = displayEmail;
        public string? Name => original.Name;
        public UserAccountState AccountState => original.AccountState;
        public Guid? TenantId => original is ITenantUser { TenantId: { } tenantId } ? tenantId : null;
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

internal sealed record IdentityServiceDependencies(
    ISecurityEventSink? SecurityEventSink = null,
    TimeProvider? TimeProvider = null);
