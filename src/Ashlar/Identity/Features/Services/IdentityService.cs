namespace Ashlar.Identity.Features.Services;

internal sealed class IdentityService(
    IUserRepository repository,
    IAuthenticationProviderRegistry providerRegistry,
    IAuthenticationPipeline authenticationPipeline)
    : IIdentityService
{
    private readonly IUserRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly IAuthenticationPipeline _authenticationPipeline = authenticationPipeline ?? throw new ArgumentNullException(nameof(authenticationPipeline));

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
}
