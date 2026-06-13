using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Authenticates one-time magic link tokens.
/// </summary>
/// <param name="tokenHasher">Hashes raw magic link tokens before lookup.</param>
public sealed class MagicLinkAuthenticationProvider(ISecureTokenHasher tokenHasher) : IPrimaryAuthenticationProvider
{
    /// <summary>
    /// Identifies credentials issued for magic link sign-in.
    /// </summary>
    public const string CredentialPurpose = "magic-link-sign-in";
    private readonly ISecureTokenHasher _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));

    /// <summary>
    /// Provider identity used for magic-link credentials.
    /// </summary>
    public AuthenticationProviderKey Key => AuthenticationProviderKey.MagicLink;

    /// <summary>
    /// Whether stored credential values require reversible protection. Magic-link credentials store token hashes.
    /// </summary>
    public bool ProtectsCredentials => false;

    /// <summary>
    /// Typical raw magic-link token length used for dummy credential work.
    /// </summary>
    public int TypicalCredentialLength => 71;

    /// <summary>
    /// Hashes the magic link token into the provider key.
    /// </summary>
    /// <param name="assertion">Caller-supplied magic-link assertion containing the raw token.</param>
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
    /// Returns the precomputed token hash that should be stored with the one-time credential.
    /// </summary>
    /// <param name="assertion">Caller-supplied magic-link assertion containing the raw token.</param>
    /// <param name="rawValue">Precomputed token hash prepared by the sign-in flow.</param>
    /// <returns>The storage lookup hash for the magic-link credential.</returns>
    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        return rawValue;
    }

    /// <summary>
    /// Finds the user linked to the magic link token.
    /// </summary>
    /// <param name="assertion">Caller-supplied magic-link assertion containing the raw token.</param>
    /// <param name="context">Authentication request context used for tenant-aware user lookup.</param>
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
    /// <param name="assertion">Magic-link assertion containing the raw token. Do not log this value.</param>
    /// <param name="credential">The credential resolved by provider key.</param>
    /// <param name="cancellationToken">A token that can cancel authentication.</param>
    /// <returns>A successful consumed-credential result when the credential is a valid magic-link credential; otherwise, a failed result.</returns>
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
