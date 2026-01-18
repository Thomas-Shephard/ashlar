using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity;

public sealed class IdentityService : IIdentityService
{
    private readonly IIdentityRepository _repository;
    private readonly ISecretProtector _secretProtector;
    private readonly string _dummyProtectedValue;
    private readonly IReadOnlyDictionary<ProviderType, IAuthenticationProvider> _providers;
    private readonly IdentityServiceOptions _options;

    public IdentityService(
        IIdentityRepository repository,
        IEnumerable<IAuthenticationProvider> providers,
        ISecretProtector secretProtector,
        IdentityServiceOptions? options = null)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _secretProtector = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
        _options = options ?? new IdentityServiceOptions();
        _dummyProtectedValue = _secretProtector.Protect(new string('D', 2048));

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

        if (!_providers.TryGetValue(assertion.ProviderType, out var provider))
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        var (user, credential) = await ResolveUserAndCredentialAsync(email, assertion, provider, tenantId, cancellationToken);
        var (unprotectedCredential, unprotectFailed) = UnprotectCredential(credential, provider);

        var result = await provider.AuthenticateAsync(assertion, unprotectedCredential, cancellationToken);
        if (unprotectFailed || result.Result is not (PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded) || user == null)
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        if (!user.IsActive)
        {
            return new AuthenticationResponse(false, user, AuthenticationStatus.Disabled);
        }

        var status = result.Result == PasswordVerificationResult.SuccessRehashNeeded ? AuthenticationStatus.SuccessRehashNeeded : AuthenticationStatus.Success;

        var lifecycleResult = await HandleCredentialLifecycleAsync(user, unprotectedCredential, credential, result, provider, cancellationToken);
        return lifecycleResult ?? new AuthenticationResponse(true, user, status, result.Claims);
    }

    private async Task<AuthenticationResponse?> HandleCredentialLifecycleAsync(
        IUser user,
        UserCredential? unprotectedCredential,
        UserCredential? originalCredential,
        AuthenticationResult result,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken)
    {
        if (unprotectedCredential == null)
        {
            return null;
        }

        if (result.IsCredentialConsumed)
        {
            try
            {
                await _repository.DeleteCredentialAsync(unprotectedCredential.Id, cancellationToken);
                return null;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // TODO: Log exception.
                // Fail authentication if we cannot guarantee the credential was consumed (prevent replay/race conditions).
                return new AuthenticationResponse(false, user);
            }
        }

        await ApplyCredentialUpdatesAsync(unprotectedCredential, originalCredential, result, provider, cancellationToken);
        return null;
    }

    private async Task ApplyCredentialUpdatesAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        AuthenticationResult result,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        bool needsUpdate = false;

        // Avoid constant DB writes for LastUsedAt if the last update was very recent.
        if (!unprotectedCredential.LastUsedAt.HasValue || (now - unprotectedCredential.LastUsedAt.Value) >= _options.LastUsedAtUpdateThreshold)
        {
            unprotectedCredential.LastUsedAt = now;
            needsUpdate = true;
        }

        if (result.NewMetadata != null && result.NewMetadata != unprotectedCredential.Metadata)
        {
            unprotectedCredential.Metadata = result.NewMetadata;
            needsUpdate = true;
        }

        if (result is { ShouldUpdateCredential: true, NewCredentialValue: not null })
        {
            unprotectedCredential.CredentialValue = provider.ProtectsCredentials
                ? _secretProtector.Protect(result.NewCredentialValue)
                : result.NewCredentialValue;
            needsUpdate = true;
        }
        else
        {
            // Preserve the original value if no update was requested or if the new credential value is null.
            // This also avoids expensive re-encryption of the existing protected value.
            unprotectedCredential.CredentialValue = originalCredential?.CredentialValue;
        }

        if (needsUpdate)
        {
            await TryUpdateCredentialAsync(unprotectedCredential, cancellationToken);
        }
    }

    private async Task<(IUser? User, UserCredential? Credential)> ResolveUserAndCredentialAsync(string email, IAuthenticationAssertion assertion, IAuthenticationProvider provider, Guid? tenantId, CancellationToken cancellationToken)
    {
        var providerName = provider.GetProviderName(assertion);

        var user = await provider.FindUserAsync(assertion, email, tenantId, _repository, cancellationToken);

        var userId = user?.Id ?? Guid.NewGuid();
        // Use assertion key if available (e.g. external auth), otherwise fallback to existing user mapping or new random for missing user.
        var providerKey = provider.GetProviderKey(assertion, userId);
        if (string.IsNullOrEmpty(providerKey))
        {
            providerKey = Guid.NewGuid().ToString();
        }

        var credential = await _repository.GetCredentialForUserAsync(userId, assertion.ProviderType, providerName, providerKey, cancellationToken);
        return (user, credential);
    }

    private (UserCredential? Credential, bool UnprotectFailed) UnprotectCredential(UserCredential? credential, IAuthenticationProvider provider)
    {
        if (!provider.ProtectsCredentials)
        {
            if (credential == null)
            {
                return (null, false);
            }

            return (new UserCredential
            {
                Id = credential.Id,
                UserId = credential.UserId,
                ProviderType = credential.ProviderType,
                ProviderName = credential.ProviderName,
                ProviderKey = credential.ProviderKey,
                CredentialValue = credential.CredentialValue,
                Metadata = credential.Metadata,
                LastUsedAt = credential.LastUsedAt
            }, false);
        }

        var valueToUnprotect = credential?.CredentialValue ?? _dummyProtectedValue;
        string? unprotectedValue = null;
        bool unprotectFailed = false;

        try
        {
            unprotectedValue = _secretProtector.Unprotect(valueToUnprotect);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            if (credential?.CredentialValue != null)
            {
                unprotectFailed = true;
            }
        }

        if (credential == null)
        {
            return (null, unprotectFailed);
        }

        var unprotectedCredential = new UserCredential
        {
            Id = credential.Id,
            UserId = credential.UserId,
            ProviderType = credential.ProviderType,
            ProviderName = credential.ProviderName,
            ProviderKey = credential.ProviderKey,
            CredentialValue = credential.CredentialValue == null || unprotectFailed ? null : unprotectedValue,
            Metadata = credential.Metadata,
            LastUsedAt = credential.LastUsedAt
        };

        return (unprotectedCredential, unprotectFailed);
    }

    private async Task TryUpdateCredentialAsync(UserCredential credential, CancellationToken cancellationToken)
    {
        try
        {
            await _repository.UpdateCredentialAsync(credential, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // TODO: Log exception. Best effort update for rehashing. If it fails, the user is still authenticated.
        }
    }

    public async Task<IUser> CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        await _repository.CreateUserAsync(user, cancellationToken);
        return user;
    }

    public async Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        var user = await _repository.GetUserByIdAsync(userId, cancellationToken);

        if (user == null)
        {
            throw new InvalidOperationException($"User with ID '{userId}' not found.");
        }

        var type = assertion.ProviderType;
        if (!_providers.TryGetValue(type, out var provider))
        {
            throw new ArgumentException($"Provider type '{type}' is not supported.", nameof(assertion));
        }

        var providerKey = provider.GetProviderKey(assertion, user.Id);
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            throw new InvalidOperationException($"Could not derive a valid provider key for provider '{type}'.");
        }

        var providerName = provider.GetProviderName(assertion);

        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

        var linkedUser = await _repository.GetUserByProviderKeyAsync(type, providerName, providerKey, cancellationToken);

        if (linkedUser != null)
        {
            if (linkedUser.Id != userId)
            {
                throw new InvalidOperationException($"The credential from '{providerName}' is already linked to another user.");
            }

            var message = type == ProviderType.Local
                ? "A local password is already linked to this user."
                : $"Credential for provider '{providerName}' is already linked to this user.";

            throw new InvalidOperationException(message);
        }

        credentialValue = provider.PrepareCredentialValue(assertion, credentialValue);

        if (provider.ProtectsCredentials && credentialValue != null)
        {
            credentialValue = _secretProtector.Protect(credentialValue);
        }

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = type,
            ProviderName = providerName,
            ProviderKey = providerKey,
            CredentialValue = credentialValue
        };

        await _repository.CreateCredentialAsync(credential, cancellationToken);
    }
}
