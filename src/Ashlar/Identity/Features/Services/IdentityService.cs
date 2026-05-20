using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Services;

/// <summary>
/// Provides identity service behavior.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <param name="providerRegistry">The provider registry value.</param>
/// <param name="credentialService">The credential service value.</param>
/// <param name="authenticationPipeline">The authentication pipeline value.</param>
/// <param name="transactionProvider">The transaction provider value.</param>
/// <param name="securityEventSink">The security event sink value.</param>
/// <param name="timeProvider">The time provider value.</param>
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

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="repository">The repository value.</param>
    /// <param name="providers">The providers value.</param>
    /// <param name="credentialService">The credential service value.</param>
    /// <param name="transactionProvider">The transaction provider value.</param>
    /// <param name="securityEventSink">The security event sink value.</param>
    /// <param name="timeProvider">The time provider value.</param>
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

    /// <summary>
    /// Initializes a configured identity service instance.
    /// </summary>
    /// <param name="repository">The repository value.</param>
    /// <param name="providerRegistry">The provider registry value.</param>
    /// <param name="credentialService">The credential service value.</param>
    /// <param name="transactionProvider">The transaction provider value.</param>
    /// <param name="securityEventSink">The security event sink value.</param>
    /// <param name="timeProvider">The time provider value.</param>
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

    /// <summary>
    /// Gets or sets the supported provider keys value.
    /// </summary>
    public IEnumerable<AuthenticationProviderKey> SupportedProviderKeys => _providerRegistry.SupportedProviderKeys;

    /// <summary>
    /// Performs the find by email <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="tenantId">The tenant id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        return await _repository.GetUserByEmailAsync(email, tenantId, cancellationToken);
    }

    /// <summary>
    /// Performs the find by provider key <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="provider">The provider value.</param>
    /// <param name="providerKey">The provider key value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IUser?> FindByProviderKeyAsync(AuthenticationProviderKey provider, string providerKey, CancellationToken cancellationToken = default)
    {
        if (provider.Type == default || string.IsNullOrWhiteSpace(provider.Name))
        {
            throw new ArgumentException("Provider key must be fully initialized with a type and name.", nameof(provider));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);

        return await _repository.GetUserByProviderKeyAsync(provider.Type, provider.Name, providerKey, cancellationToken);
    }

    /// <summary>
    /// Performs the login <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="context">The context value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default)
    {
        return await _authenticationPipeline.LoginAsync(context, assertion, cancellationToken);
    }

    /// <summary>
    /// Performs the create user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Performs the link credential <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="credentialValue">The credential value value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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
        var email = IdentityNormalization.SanitizeEmailForDelivery(user.Email);
        return string.Equals(email, user.Email, StringComparison.Ordinal)
            ? user
            : new SanitizedUserWrapper(user, email);
    }

    private sealed class SanitizedUserWrapper(IUser original, string email) : ITenantUser, IHasAuditMetadata
    {
        /// <summary>
        /// Gets or sets the id value.
        /// </summary>
        public Guid Id => original.Id;
        /// <summary>
        /// Gets or sets the email value.
        /// </summary>
        public string Email { get; } = email;
        /// <summary>
        /// Gets or sets the name value.
        /// </summary>
        public string? Name => original.Name;
        /// <summary>
        /// Gets or sets the is active value.
        /// </summary>
        public bool IsActive => original.IsActive;
        /// <summary>
        /// Gets or sets the tenant id value.
        /// </summary>
        public Guid? TenantId => (original as ITenantUser)?.TenantId;
        /// <summary>
        /// Gets or sets the email verified at value.
        /// </summary>
        public DateTimeOffset? EmailVerifiedAt => original.EmailVerifiedAt;
        /// <summary>
        /// Gets or sets the created at value.
        /// </summary>
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



