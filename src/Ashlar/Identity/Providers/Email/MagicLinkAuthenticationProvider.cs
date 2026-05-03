using System.Security.Cryptography;
using System.Text;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Providers.Email;

public sealed class MagicLinkAuthenticationProvider(ISecureTokenHasher tokenHasher) : IAuthenticationProvider
{
    public const string CredentialPurpose = "magic-link-sign-in";

    public AuthenticationProviderKey Key => AuthenticationProviderKey.MagicLink;

    public bool ProtectsCredentials => true;

    public int TypicalCredentialLength => 64;

    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        return userId.ToString("D");
    }

    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        return rawValue != null ? tokenHasher.HashToken(rawValue) : null;
    }

    public async Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(repository);

        if (assertion is not MagicLinkAssertion || string.IsNullOrWhiteSpace(context.Email))
        {
            return null;
        }

        return await repository.GetUserByEmailAsync(context.Email, context.TenantId, cancellationToken);
    }

    public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (assertion is not MagicLinkAssertion magicLinkAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        if (credential is not { Purpose: CredentialPurpose, CredentialValue: not null })
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        var hashedToken = tokenHasher.HashToken(magicLinkAssertion.Token);
        var success = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(hashedToken),
            Encoding.UTF8.GetBytes(credential.CredentialValue));

        var status = success ? AuthenticationResultStatus.Succeeded : AuthenticationResultStatus.Failed;
        return Task.FromResult(new AuthenticationResult(status, IsCredentialConsumed: success));
    }
}
