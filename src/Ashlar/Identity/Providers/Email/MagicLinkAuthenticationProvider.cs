using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Provides magic link authentication provider behavior.
/// </summary>
/// <param name="tokenHasher">The token hasher value.</param>
public sealed class MagicLinkAuthenticationProvider(ISecureTokenHasher tokenHasher) : IAuthenticationProvider
{
    /// <summary>
    /// Defines the credential purpose value.
    /// </summary>
    public const string CredentialPurpose = "magic-link-sign-in";
    private readonly ISecureTokenHasher _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));

    /// <summary>
    /// Gets or sets the key value.
    /// </summary>
    public AuthenticationProviderKey Key => AuthenticationProviderKey.MagicLink;

    /// <summary>
    /// Gets or sets the protects credentials value.
    /// </summary>
    public bool ProtectsCredentials => false;

    /// <summary>
    /// Gets or sets the typical credential length value.
    /// </summary>
    public int TypicalCredentialLength => 71;

    /// <summary>
    /// Performs the get provider key operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="userId">The user id value.</param>
    /// <returns>The operation result.</returns>
    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        if (assertion is not MagicLinkAssertion magicLinkAssertion)
        {
            return string.Empty;
        }

        return _tokenHasher.HashToken(magicLinkAssertion.Token);
    }

    /// <summary>
    /// Performs the prepare credential value operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="rawValue">The raw value value.</param>
    /// <returns>The operation result.</returns>
    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        return rawValue;
    }

    /// <summary>
    /// Performs the find user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="repository">The repository value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default)
    {
        if (assertion is not MagicLinkAssertion magicLinkAssertion)
        {
            return null;
        }

        var providerKey = _tokenHasher.HashToken(magicLinkAssertion.Token);
        return await repository.GetUserByProviderKeyAsync(Key.Type, Key.Name, providerKey, cancellationToken);
    }

    /// <summary>
    /// Performs the authenticate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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
