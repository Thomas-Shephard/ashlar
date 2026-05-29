using Ashlar.Auditing;
using Microsoft.Extensions.Logging;

namespace Ashlar.Identity.Features.Services;

/// <summary>
/// Coordinates user creation, lookup, authentication, and credential linking.
/// </summary>
/// <param name="repository">The repository used to read and write users.</param>
/// <param name="providerRegistry">The authentication provider registry used for provider lookup.</param>
/// <param name="credentialService">The credential service used for credential lifecycle operations.</param>
/// <param name="authenticationPipeline">The pipeline used to validate authentication assertions.</param>
/// <param name="transactionProvider">The transaction provider used to commit multi-step identity operations.</param>
/// <param name="securityEventSink">Optional sink for identity security events.</param>
/// <param name="timeProvider">Optional clock used when emitting time-stamped security events.</param>
/// <param name="loggerFactory">Optional logger factory used for security event sink failures.</param>
public sealed class IdentityService(
    IUserRepository repository,
    IAuthenticationProviderRegistry providerRegistry,
    ICredentialService credentialService,
    IAuthenticationPipeline authenticationPipeline,
    IAshlarTransactionProvider transactionProvider,
    ISecurityEventSink? securityEventSink = null,
    TimeProvider? timeProvider = null,
    ILoggerFactory? loggerFactory = null)
    : IIdentityService
{
    private readonly IUserRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly ICredentialService _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly IAuthenticationPipeline _authenticationPipeline = authenticationPipeline ?? throw new ArgumentNullException(nameof(authenticationPipeline));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly SecurityEventEmitter _securityEvents = new(securityEventSink, timeProvider, loggerFactory);

    /// <summary>
    /// Gets the authentication providers supported by this identity service.
    /// </summary>
    public IEnumerable<AuthenticationProviderKey> SupportedProviderKeys => _providerRegistry.SupportedProviderKeys;

    /// <summary>
    /// Finds a user by email address, optionally scoped to a tenant.
    /// </summary>
    /// <param name="email">The email address to search for.</param>
    /// <param name="tenantId">The tenant scope for the lookup, or <see langword="null" /> for tenantless users.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The matching user, or <see langword="null" /> when no user exists.</returns>
    public async Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        return await _repository.GetUserByEmailAsync(email, tenantId, cancellationToken);
    }

    /// <summary>
    /// Finds the user linked to an external authentication provider key.
    /// </summary>
    /// <param name="provider">The authentication provider that owns the key.</param>
    /// <param name="providerKey">The provider-specific key assigned to the user.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The linked user, or <see langword="null" /> when no active credential matches.</returns>
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
    /// Authenticates a user with the configured authentication pipeline.
    /// </summary>
    /// <param name="context">Request context for the authentication attempt.</param>
    /// <param name="assertion">The provider assertion to validate.</param>
    /// <param name="cancellationToken">A token that can cancel authentication.</param>
    /// <returns>The authentication response produced by the pipeline.</returns>
    public async Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default)
    {
        return await _authenticationPipeline.LoginAsync(context, assertion, cancellationToken);
    }

    /// <summary>
    /// Creates a user and records the corresponding security event after commit.
    /// </summary>
    /// <param name="user">The user to create.</param>
    /// <param name="cancellationToken">A token that can cancel user creation.</param>
    /// <returns>The created user with a sanitized email address when normalization changed it.</returns>
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
    /// Links an authentication credential to an existing user.
    /// </summary>
    /// <param name="userId">The user that will own the credential.</param>
    /// <param name="assertion">The assertion describing the credential provider and key.</param>
    /// <param name="credentialValue">Optional protected credential value to store.</param>
    /// <param name="cancellationToken">A token that can cancel credential linking.</param>
    /// <returns>A success result when the credential is linked; otherwise, a failure describing the problem.</returns>
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
        /// Gets the user identifier.
        /// </summary>
        public Guid Id => original.Id;
        /// <summary>
        /// Gets the sanitized email address.
        /// </summary>
        public string Email { get; } = email;
        /// <summary>
        /// Gets the user's display name.
        /// </summary>
        public string? Name => original.Name;
        /// <summary>
        /// Gets whether the user is active.
        /// </summary>
        public bool IsActive => original.IsActive;
        /// <summary>
        /// Gets the tenant that owns the user.
        /// </summary>
        public Guid? TenantId => (original as ITenantUser)?.TenantId;
        /// <summary>
        /// Gets when the user's email address was verified.
        /// </summary>
        public DateTimeOffset? EmailVerifiedAt => original.EmailVerifiedAt;
        /// <summary>
        /// Gets the original user creation timestamp.
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
