using System.Collections.Concurrent;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Encryption;

namespace Ashlar.Identity;

/// <summary>
/// Implements credential management services including resolution, linking, and lifecycle updates.
/// </summary>
/// <remarks>
/// This service implements timing attack resistance by ensuring that unprotection operations
/// are performed even when a user or credential is not found, using provider-specific dummy values.
/// </remarks>
public sealed class CredentialService(
    IIdentityRepository repository,
    ISecretProtector secretProtector,
    IdentityServiceOptions? options = null)
    : ICredentialService
{
    private readonly IIdentityRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly ISecretProtector _secretProtector = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
    private readonly IdentityServiceOptions _options = options ?? new IdentityServiceOptions();
    private readonly ConcurrentDictionary<int, string> _dummyValues = new();

    /// <inheritdoc />
    public async Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(
        string email,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        Guid? tenantId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(provider);

        var providerName = provider.GetProviderName(assertion);
        var user = await provider.FindUserAsync(assertion, email, tenantId, _repository, cancellationToken);

        var userId = user?.Id ?? Guid.NewGuid();
        var providerKey = provider.GetProviderKey(assertion, userId);
        if (string.IsNullOrEmpty(providerKey))
        {
            providerKey = Guid.NewGuid().ToString();
        }

        var credential = await _repository.GetCredentialForUserAsync(userId, assertion.ProviderType, providerName, providerKey, cancellationToken);
        var (unprotectedCredential, unprotectFailed) = UnprotectCredential(credential, provider);
        return (user, unprotectedCredential, credential, unprotectFailed);
    }

    /// <inheritdoc />
    public async Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(provider);

        var providerName = provider.GetProviderName(assertion);
        var user = await _repository.GetUserByIdAsync(userId, cancellationToken);

        var providerKey = provider.GetProviderKey(assertion, userId);
        if (string.IsNullOrEmpty(providerKey))
        {
            providerKey = Guid.NewGuid().ToString();
        }

        var credential = await _repository.GetCredentialForUserAsync(userId, assertion.ProviderType, providerName, providerKey, cancellationToken);
        var (unprotectedCredential, unprotectFailed) = UnprotectCredential(credential, provider);
        return (user, unprotectedCredential, credential, unprotectFailed);
    }

    /// <summary>
    /// Unprotects the credential value if the provider requires protection.
    /// </summary>
    /// <param name="credential">The credential to unprotect.</param>
    /// <param name="provider">The authentication provider.</param>
    /// <returns>A tuple containing the unprotected credential and a flag indicating if unprotection failed.</returns>
    /// <remarks>
    /// This method is timing-safe. If the <paramref name="credential"/> is null, it performs an unprotection
    /// operation on a cached dummy value matching the provider's typical credential length.
    /// </remarks>
    private (UserCredential? Credential, bool UnprotectFailed) UnprotectCredential(UserCredential? credential, IAuthenticationProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

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

        var valueToUnprotect = credential?.CredentialValue ?? _dummyValues.GetOrAdd(provider.TypicalCredentialLength, len => _secretProtector.Protect(new string('D', len)));

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

    /// <inheritdoc />
    public async Task UpdateCredentialUsageAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        AuthenticationResult result,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(unprotectedCredential);
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(provider);

        if (result.IsCredentialConsumed)
        {
            await _repository.DeleteCredentialAsync(unprotectedCredential.Id, cancellationToken);
            return;
        }

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
        else if (originalCredential != null)
        {
            // Preserve the original value if no update was requested or if the new credential value is null.
            // This also avoids expensive re-encryption of the existing protected value.
            unprotectedCredential.CredentialValue = originalCredential.CredentialValue;
        }

        if (needsUpdate)
        {
            try
            {
                await _repository.UpdateCredentialAsync(unprotectedCredential, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // TODO: Log exception. Best effort update for rehashing. If it fails, the user is still authenticated.
            }
        }
    }

    /// <inheritdoc />
    public async Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, string? credentialValue = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(provider);

        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        var user = await _repository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null)
        {
            throw new InvalidOperationException($"User with ID '{userId}' not found.");
        }

        var providerKey = provider.GetProviderKey(assertion, userId);
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

            var message = assertion.ProviderType == ProviderType.Local
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
            ProviderType = assertion.ProviderType,
            ProviderName = providerName,
            ProviderKey = providerKey,
            CredentialValue = credentialValue
        };

        await _repository.CreateCredentialAsync(credential, cancellationToken);
    }
}
