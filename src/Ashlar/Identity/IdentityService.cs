using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity;

public sealed class IdentityService : IIdentityService
{
    private readonly IIdentityRepository _repository;
    private readonly ISecretProtector _secretProtector;
    private readonly string _dummyProtectedValue;
    private readonly IReadOnlyDictionary<ProviderType, IAuthenticationProvider> _providers;

    public IdentityService(IIdentityRepository repository, IEnumerable<IAuthenticationProvider> providers, ISecretProtector secretProtector)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _secretProtector = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
        _dummyProtectedValue = _secretProtector.Protect("DUMMY_PAYLOAD_TO_MAINTAIN_TIMING");

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

        IUser? user;
        UserCredential? credential;

        if (assertion is ExternalIdentityAssertion external)
        {
            user = await _repository.GetUserByProviderKeyAsync(external.Type, external.ProviderName, external.ProviderKey, cancellationToken);

            // Prevent user enumeration by ensuring a DB call happens regardless of user existence.
            var userId = user?.Id ?? Guid.NewGuid();
            credential = await _repository.GetCredentialForUserAsync(userId, assertion.ProviderType, external.ProviderName, external.ProviderKey, cancellationToken);
        }
        else
        {
            user = string.IsNullOrWhiteSpace(email) ? null : await _repository.GetUserByEmailAsync(email, tenantId, cancellationToken);

            // Prevent user enumeration by ensuring a DB call happens regardless of user existence.
            var userId = user?.Id ?? Guid.NewGuid();

            // For local, we need a key. If user is null, we generate a dummy key to sustain timing.
            var providerKey = user != null ? provider.GetProviderKey(assertion, user) : Guid.NewGuid().ToString();
            credential = await _repository.GetCredentialForUserAsync(userId, assertion.ProviderType, assertion.ProviderType.Value, providerKey, cancellationToken);
        }

        bool unprotectFailed = false;
        if (assertion.ProviderType != ProviderType.Local)
        {
            // Always perform an unprotect operation (or a dummy one) to mitigate timing-based user enumeration.
            var valueToUnprotect = credential?.CredentialValue ?? _dummyProtectedValue;
            string? unprotected = null;
            try
            {
                unprotected = _secretProtector.Unprotect(valueToUnprotect);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                unprotectFailed = credential?.CredentialValue != null;
            }

            if (credential != null && credential.CredentialValue != null)
            {
                // Create a new instance to avoid mutating a potentially tracked entity with plain-text data.
                credential = new UserCredential
                {
                    Id = credential.Id,
                    UserId = credential.UserId,
                    ProviderType = credential.ProviderType,
                    ProviderName = credential.ProviderName,
                    ProviderKey = credential.ProviderKey,
                    CredentialValue = unprotectFailed ? null : unprotected
                };
            }
        }

        var result = await provider.AuthenticateAsync(assertion, credential, cancellationToken);
        if (unprotectFailed || result.Result is not (PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded) || user == null)
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        if (!user.IsActive)
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Disabled);
        }

        var status = result.Result == PasswordVerificationResult.SuccessRehashNeeded ? AuthenticationStatus.SuccessRehashNeeded : AuthenticationStatus.Success;

        if (!result.ShouldUpdateCredential || result.NewCredentialValue == null || credential == null)
        {
            return new AuthenticationResponse(true, user, status, result.Claims);
        }

        try
        {
            var valueToStore = result.NewCredentialValue;
            if (assertion.ProviderType != ProviderType.Local)
            {
                valueToStore = _secretProtector.Protect(valueToStore);
            }

            credential.CredentialValue = valueToStore;
            await _repository.UpdateCredentialAsync(credential, cancellationToken);
        }
        catch (Exception)
        {
            // TODO: Log exception. Best effort update for rehashing. If it fails, the user is still authenticated.
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

        var providerKey = provider.GetProviderKey(assertion, user);
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            throw new InvalidOperationException($"Could not derive a valid provider key for provider '{type}'.");
        }

        var providerName = assertion is ExternalIdentityAssertion external
            ? external.ProviderName
            : type.Value;

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

        if (type != ProviderType.Local && credentialValue != null)
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
