using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Authenticates one-time magic link tokens.
/// </summary>
/// <param name="tokenHasher">Hashes raw magic link tokens before lookup.</param>
public sealed class MagicLinkAuthenticationProvider(ISecureTokenHasher tokenHasher) : IAuthenticationProvider
{
    /// <summary>
    /// Identifies credentials issued for magic link sign-in.
    /// </summary>
    public const string CredentialPurpose = "magic-link-sign-in";
    private readonly ISecureTokenHasher _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));

    /// <summary>
    /// Gets the provider key.
    /// </summary>
    public AuthenticationProviderKey Key => AuthenticationProviderKey.MagicLink;

    /// <summary>
    /// Gets whether credential values should be encrypted before storage.
    /// </summary>
    public bool ProtectsCredentials => false;

    /// <summary>
    /// Gets the typical raw token length.
    /// </summary>
    public int TypicalCredentialLength => 71;

    /// <summary>
    /// Hashes the magic link token into the provider key.
    /// </summary>
    /// <param name="assertion">The magic link assertion.</param>
    /// <param name="userId">Unused for magic link tokens.</param>
    /// <returns>The token hash, or an empty string for unsupported assertions.</returns>
    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        if (assertion is not MagicLinkAssertion magicLinkAssertion)
        {
            return string.Empty;
        }

        return SecureTokenHashing.TryHashToken(_tokenHasher, magicLinkAssertion.Token, out var providerKey)
            ? providerKey
            : string.Empty;
    }

    /// <summary>
    /// Returns the raw token hash value to store with the credential.
    /// </summary>
    /// <param name="assertion">The magic link assertion.</param>
    /// <param name="rawValue">The raw value prepared by the sign-in flow.</param>
    /// <returns>The value to store for later authentication.</returns>
    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        return rawValue;
    }

    /// <summary>
    /// Finds the user linked to the magic link token.
    /// </summary>
    /// <param name="assertion">The magic link assertion.</param>
    /// <param name="context">The authentication request context.</param>
    /// <param name="repository">The user repository.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The linked user, or <see langword="null" /> when the assertion is unsupported or unlinked.</returns>
    public async Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IUserRepository repository, CancellationToken cancellationToken = default)
    {
        if (assertion is not MagicLinkAssertion magicLinkAssertion)
        {
            return null;
        }

        if (!SecureTokenHashing.TryHashToken(_tokenHasher, magicLinkAssertion.Token, out var providerKey))
        {
            return null;
        }

        return await repository.GetUserByProviderKeyAsync(Key.Type, Key.Name, providerKey, cancellationToken);
    }

    /// <summary>
    /// Validates that the resolved credential was issued for magic link sign-in.
    /// </summary>
    /// <param name="assertion">The magic link assertion.</param>
    /// <param name="credential">The credential resolved by provider key.</param>
    /// <param name="cancellationToken">A token that can cancel authentication.</param>
    /// <returns>The authentication result.</returns>
    public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not MagicLinkAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        if (credential is not { Purpose: CredentialPurpose })
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        // The token hash is stored as the ProviderKey, so if we reached here, the token matches the hash.
        // We can just return success.
        return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));
    }
}
