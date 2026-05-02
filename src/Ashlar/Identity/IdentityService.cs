using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

public sealed class IdentityService : IIdentityService
{
    private readonly IIdentityRepository _repository;
    private readonly ICredentialService _credentialService;
    private readonly IAuthenticationProviderRegistry _providerRegistry;
    private readonly IAuthenticationPipeline _authenticationPipeline;

    public IdentityService(
        IIdentityRepository repository,
        IEnumerable<IAuthenticationProvider> providers,
        ICredentialService credentialService)
        : this(repository, new AuthenticationProviderRegistry(providers), credentialService)
    {
    }

    public IdentityService(
        IIdentityRepository repository,
        IAuthenticationProviderRegistry providerRegistry,
        ICredentialService credentialService)
        : this(repository, providerRegistry, credentialService, new AuthenticationPipeline(providerRegistry, credentialService))
    {
    }

    public IdentityService(
        IIdentityRepository repository,
        IAuthenticationProviderRegistry providerRegistry,
        ICredentialService credentialService,
        IAuthenticationPipeline authenticationPipeline)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
        _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
        _authenticationPipeline = authenticationPipeline ?? throw new ArgumentNullException(nameof(authenticationPipeline));
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
        await _repository.CreateUserAsync(user, cancellationToken);
        return user;
    }

    public async Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_providerRegistry.TryGetProvider(assertion, out var provider))
        {
            throw new ArgumentException($"Provider '{assertion.ProviderIdentity}' is not supported.", nameof(assertion));
        }

        await _credentialService.LinkCredentialAsync(userId, assertion, provider, credentialValue, cancellationToken);
    }
}
