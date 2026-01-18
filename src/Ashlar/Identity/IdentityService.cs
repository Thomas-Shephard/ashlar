using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity;

public sealed class IdentityService : IIdentityService
{
    private readonly IIdentityRepository _repository;
    private readonly ICredentialService _credentialService;
    private readonly IReadOnlyDictionary<ProviderType, IAuthenticationProvider> _providers;

    public IdentityService(
        IIdentityRepository repository,
        IEnumerable<IAuthenticationProvider> providers,
        ICredentialService credentialService)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));

        var dict = new Dictionary<ProviderType, IAuthenticationProvider>();

        if ((providers ?? throw new ArgumentNullException(nameof(providers))).Any(provider => !dict.TryAdd(provider.SupportedType, provider)))
        {
            throw new ArgumentException("Duplicate provider registered for type", nameof(providers));
        }

        _providers = dict;
    }

    public IEnumerable<ProviderType> SupportedProviderTypes => _providers.Keys;

    public async Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        return await _repository.GetUserByEmailAsync(email, tenantId, cancellationToken);
    }

    public async Task<IUser?> FindByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
    {
        return await _repository.GetUserByProviderKeyAsync(type, providerName, providerKey, cancellationToken);
    }

    public async Task<AuthenticationResponse> LoginAsync(string email, IAuthenticationAssertion assertion, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        if (!_providers.TryGetValue(assertion.ProviderType, out var provider))
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        var (user, credential, originalCredential, unprotectFailed) = await _credentialService.ResolveAsync(email, assertion, provider, tenantId, cancellationToken);

        var result = await provider.AuthenticateAsync(assertion, credential, cancellationToken);
        if (unprotectFailed || result.Result is not (PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded) || user == null)
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        if (!user.IsActive)
        {
            return new AuthenticationResponse(false, user, AuthenticationStatus.Disabled);
        }

        var status = result.Result == PasswordVerificationResult.SuccessRehashNeeded ? AuthenticationStatus.SuccessRehashNeeded : AuthenticationStatus.Success;

        if (credential == null)
        {
            return new AuthenticationResponse(true, user, status, result.Claims);
        }

        try
        {
            await _credentialService.UpdateCredentialUsageAsync(credential, originalCredential, result, provider, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (result.IsCredentialConsumed)
            {
                // Fail authentication if we cannot guarantee the credential was consumed (prevent replay/race conditions).
                return new AuthenticationResponse(false, user);
            }
        }

        return new AuthenticationResponse(true, user, status, result.Claims);
    }

    public async Task<IUser> CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        await _repository.CreateUserAsync(user, cancellationToken);
        return user;
    }

    public async Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_providers.TryGetValue(assertion.ProviderType, out var provider))
        {
            throw new ArgumentException($"Provider type '{assertion.ProviderType}' is not supported.", nameof(assertion));
        }

        await _credentialService.LinkCredentialAsync(userId, assertion, provider, credentialValue, cancellationToken);
    }
}
