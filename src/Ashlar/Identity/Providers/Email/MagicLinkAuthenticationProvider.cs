using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

public sealed class MagicLinkAuthenticationProvider(ISecureTokenHasher tokenHasher) : IAuthenticationProvider
{
    public const string CredentialPurpose = "magic-link-sign-in";
    private readonly ISecureTokenHasher _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));

    public AuthenticationProviderKey Key => AuthenticationProviderKey.MagicLink;

    public bool ProtectsCredentials => false;

    public int TypicalCredentialLength => 71;

    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        if (assertion is not MagicLinkAssertion magicLinkAssertion)
        {
            return string.Empty;
        }

        return _tokenHasher.HashToken(magicLinkAssertion.Token);
    }

    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        return rawValue;
    }

    public async Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default)
    {
        if (assertion is not MagicLinkAssertion magicLinkAssertion)
        {
            return null;
        }

        var providerKey = _tokenHasher.HashToken(magicLinkAssertion.Token);
        return await repository.GetUserByProviderKeyAsync(Key.Type, Key.Name, providerKey, cancellationToken);
    }

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
