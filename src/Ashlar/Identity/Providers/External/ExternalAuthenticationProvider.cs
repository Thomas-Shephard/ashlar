using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.External;

public abstract class ExternalAuthenticationProvider(ProviderType supportedType, string providerName) : IAuthenticationProvider
{
    public AuthenticationProviderKey Key { get; } = new(supportedType, providerName);

    public virtual bool ProtectsCredentials => true;

    public virtual int TypicalCredentialLength => 256;

    public virtual string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (assertion is ExternalIdentityAssertion externalAssertion)
        {
            return externalAssertion.ProviderKey;
        }

        return string.Empty;
    }

    public virtual string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        return rawValue;
    }

    public virtual async Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(repository);

        if (assertion is not ExternalIdentityAssertion externalAssertion)
        {
            return null;
        }

        var user = await repository.GetUserByProviderKeyAsync(Key.Type, Key.Name, externalAssertion.ProviderKey, cancellationToken);

        switch (user)
        {
            case null:
                return null;
            case ITenantUser tenantUser:
            {
                if (tenantUser.TenantId != context.TenantId)
                {
                    return null;
                }

                break;
            }
            default:
            {
                if (context.TenantId.HasValue)
                {
                    // User is a global user (not ITenantUser), but a specific tenant was requested.
                    return null;
                }

                break;
            }
        }

        return user;
    }

    public virtual Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (assertion is not ExternalIdentityAssertion externalAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        if (externalAssertion.ProviderIdentity != Key)
        {
            throw new ArgumentException($"Mismatching provider identity. Expected {Key}, got {externalAssertion.ProviderIdentity}");
        }

        // For external providers, if we received the assertion, it's typically already validated by the infrastructure layer (e.g., JWT middleware or SAML handler).
        // Here we just confirm that the credential matches.
        if (credential == null || credential.ProviderType == default || string.IsNullOrWhiteSpace(credential.ProviderName))
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        var credentialIdentity = new AuthenticationProviderKey(credential.ProviderType, credential.ProviderName);
        if (credentialIdentity != Key)
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Succeeded, Claims: externalAssertion.Claims));
    }
}

public sealed class OidcAuthenticationProvider(string providerName) : ExternalAuthenticationProvider(ProviderType.Oidc, providerName)
{
    public override int TypicalCredentialLength => 512;
}

public sealed class OAuthAuthenticationProvider(string providerName) : ExternalAuthenticationProvider(ProviderType.OAuth, providerName);

public sealed class Saml2AuthenticationProvider(string providerName) : ExternalAuthenticationProvider(ProviderType.Saml2, providerName)
{
    public override int TypicalCredentialLength => 3072;
}
