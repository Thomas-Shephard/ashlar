using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.External;

public abstract class ExternalAuthenticationProvider(ProviderType supportedType) : IAuthenticationProvider
{
    public ProviderType SupportedType => supportedType;
    public bool IsPrimary => true;

    public virtual string GetProviderName(IAuthenticationAssertion assertion)
    {
        if (assertion is ExternalIdentityAssertion externalAssertion)
        {
            return externalAssertion.ProviderName;
        }

        return SupportedType.Value;
    }

    public virtual string? GetProviderKey(IAuthenticationAssertion assertion, IUser user)
    {
        if (assertion is ExternalIdentityAssertion externalAssertion)
        {
            return externalAssertion.ProviderKey;
        }

        return null;
    }

    public virtual string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        return rawValue;
    }

    public virtual Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion? assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not ExternalIdentityAssertion externalAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion?.GetType().Name ?? "null"}", nameof(assertion));
        }

        if (externalAssertion.ProviderType != SupportedType)
        {
            throw new ArgumentException($"Mismatching provider type. Expected {SupportedType}, got {externalAssertion.ProviderType}");
        }

        // For external providers, if we received the assertion, it's typically already validated by the infrastructure layer (e.g., JWT middleware or SAML handler).
        // Here we just confirm that the credential matches.
        if (credential == null || credential.ProviderName != externalAssertion.ProviderName)
        {
            return Task.FromResult(new AuthenticationResult(PasswordVerificationResult.Failed));
        }

        return Task.FromResult(new AuthenticationResult(PasswordVerificationResult.Success, Claims: externalAssertion.Claims));
    }
}

public sealed class OidcAuthenticationProvider() : ExternalAuthenticationProvider(ProviderType.Oidc);
public sealed class OAuthAuthenticationProvider() : ExternalAuthenticationProvider(ProviderType.OAuth);
public sealed class Saml2AuthenticationProvider() : ExternalAuthenticationProvider(ProviderType.Saml2);
