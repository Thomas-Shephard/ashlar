using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.Fido2;
using Ashlar.Security.Encryption;

namespace Ashlar.Identity;

public sealed class CredentialService : ICredentialService
{
    private readonly IIdentityRepository _repository;
    private readonly ISecretProtector _secretProtector;
    private readonly string _dummyProtectedValue;
    private readonly Dictionary<ProviderType, IAuthenticationProvider> _providers;

    public CredentialService(
        IIdentityRepository repository,
        ISecretProtector secretProtector,
        IEnumerable<IAuthenticationProvider> providers)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _secretProtector = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
        _dummyProtectedValue = _secretProtector.Protect(new string('D', 64));

        var dict = new Dictionary<ProviderType, IAuthenticationProvider>();
        foreach (var provider in providers)
        {
            dict.TryAdd(provider.SupportedType, provider);
        }
        _providers = dict;
    }

    public async Task<(IUser? User, UserCredential? Credential, bool UnprotectFailed)> ResolveAsync(
        string? email,
        IAuthenticationAssertion assertion,
        Guid? tenantId = null,
        CancellationToken cancellationToken = default)
    {
        if (!_providers.TryGetValue(assertion.ProviderType, out var provider))
        {
            return (null, null, false);
        }

        IUser? user;
        UserCredential? credential;

        if (assertion is Fido2Assertion fido && string.IsNullOrWhiteSpace(email) && fido.UserHandle is { Length: > 0 and <= 64 })
        {
            // Support for "Usernameless" / "Discovery" flows via UserHandle
            // We treat the UserHandle as a special ProviderKey to find the user.
            var handleKey = Convert.ToBase64String(fido.UserHandle);
            user = await _repository.GetUserByProviderKeyAsync(assertion.ProviderType, "FIDO2_HANDLE", handleKey, cancellationToken);

            var userId = user?.Id ?? Guid.NewGuid();
            var providerKey = user != null ? provider.GetProviderKey(assertion, user) : Convert.ToBase64String(new byte[32]);
            var providerName = provider.GetProviderName(assertion);
            credential = await _repository.GetCredentialForUserAsync(userId, assertion.ProviderType, providerName, providerKey, cancellationToken);
        }
        else
        {
            user = string.IsNullOrWhiteSpace(email) 
                ? (assertion is ExternalIdentityAssertion e 
                    ? await _repository.GetUserByProviderKeyAsync(e.Type, e.ProviderName, e.ProviderKey, cancellationToken)
                    : null)
                : await _repository.GetUserByEmailAsync(email, tenantId, cancellationToken);

            var userId = user?.Id ?? Guid.NewGuid();
            var providerKey = user != null ? provider.GetProviderKey(assertion, user) : Convert.ToBase64String(new byte[32]);
            var providerName = provider.GetProviderName(assertion);
            credential = await _repository.GetCredentialForUserAsync(userId, assertion.ProviderType, providerName, providerKey, cancellationToken);
        }

        var (unprotectedCredential, unprotectFailed) = UnprotectCredential(credential, provider);
        return (user, unprotectedCredential, unprotectFailed);
    }

    public async Task<(IUser? User, UserCredential? Credential, bool UnprotectFailed)> ResolveAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default)
    {
        if (!_providers.TryGetValue(assertion.ProviderType, out var provider))
        {
            return (null, null, false);
        }

        var user = await _repository.GetUserByIdAsync(userId, cancellationToken);
        var providerKey = user != null ? provider.GetProviderKey(assertion, user) : Convert.ToBase64String(new byte[32]);
        
        var providerName = provider.GetProviderName(assertion);

        var credential = await _repository.GetCredentialForUserAsync(userId, assertion.ProviderType, providerName, providerKey, cancellationToken);
        
        var (unprotectedCredential, unprotectFailed) = UnprotectCredential(credential, provider);
        return (user, unprotectedCredential, unprotectFailed);
    }

    private (UserCredential? Credential, bool UnprotectFailed) UnprotectCredential(UserCredential? credential, IAuthenticationProvider provider)
    {
        // Local passwords are not protected by ISecretProtector (they are hashed)
        if (!provider.ProtectsCredentials)
        {
            return (credential, false);
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
            LastUsedAt = credential.LastUsedAt,
            Metadata = credential.Metadata
        };

        return (unprotectedCredential, unprotectFailed);
    }

    public async Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        var user = await _repository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null) throw new InvalidOperationException($"User with ID '{userId}' not found.");

        if (!_providers.TryGetValue(assertion.ProviderType, out var provider))
        {
            throw new ArgumentException($"Provider type '{assertion.ProviderType}' is not supported.", nameof(assertion));
        }

        var providerKey = provider.GetProviderKey(assertion, user);
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            throw new InvalidOperationException($"Could not derive a valid provider key for provider '{assertion.ProviderType}'.");
        }

        var providerName = provider.GetProviderName(assertion);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

        var linkedUser = await _repository.GetUserByProviderKeyAsync(assertion.ProviderType, providerName, providerKey, cancellationToken);
        if (linkedUser != null)
        {
            if (linkedUser.Id != userId)
            {
                throw new InvalidOperationException($"The credential from '{providerName}' is already linked to another user.");
            }

            // Idempotency: If already linked to this user, do nothing.
            return;
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
            ProviderType = assertion.ProviderType,
            ProviderName = providerName,
            ProviderKey = providerKey,
            CredentialValue = credentialValue
        };

        await _repository.CreateCredentialAsync(credential, cancellationToken);

        // Special Case: For FIDO2, also ensure the UserHandle discovery mapping exists.
        if (assertion is Fido2Assertion fido && fido.UserHandle is { Length: > 0 })
        {
            var handleKey = Convert.ToBase64String(fido.UserHandle);
            var existingHandleMapping = await _repository.GetUserByProviderKeyAsync(assertion.ProviderType, "FIDO2_HANDLE", handleKey, cancellationToken);
            
            if (existingHandleMapping == null)
            {
                await _repository.CreateCredentialAsync(new UserCredential
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    ProviderType = assertion.ProviderType,
                    ProviderName = "FIDO2_HANDLE",
                    ProviderKey = handleKey,
                    CredentialValue = null
                }, cancellationToken);
            }
        }
    }

    public async Task UpdateCredentialUsageAsync(UserCredential? credential, AuthenticationResult result, IAuthenticationProvider provider, CancellationToken cancellationToken = default)
    {
        if (credential == null || result.IsCredentialConsumed)
        {
            return;
        }

        try
        {
            if (result is { ShouldUpdateCredential: true, NewCredentialValue: not null })
            {
                credential.CredentialValue = provider.ProtectsCredentials
                    ? _secretProtector.Protect(result.NewCredentialValue)
                    : result.NewCredentialValue;
            }

            if (result.NewMetadata != null)
            {
                credential.Metadata = result.NewMetadata;
            }

            credential.LastUsedAt = DateTimeOffset.UtcNow;
            await _repository.UpdateCredentialAsync(credential, cancellationToken);
        }
        catch (Exception)
        {
            // TODO: Log exception properly (e.g., _logger.LogError(ex, "Failed to update credential metadata"))
            // Best effort update
        }
    }
}