
namespace Ashlar.Identity.Providers.External;

/// <summary>
/// Provides external authentication provider behavior.
/// </summary>
/// <param name="supportedType">The supported type value.</param>
/// <param name="providerName">The provider name value.</param>
public abstract class ExternalAuthenticationProvider(ProviderType supportedType, string providerName) : IAuthenticationProvider
{
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    public AuthenticationProviderKey Key { get; } = new(supportedType, providerName);

    /// <summary>
    /// Gets or sets the protects credentials value.
    /// </summary>
    public virtual bool ProtectsCredentials => true;

    /// <summary>
    /// Gets or sets the typical credential length value.
    /// </summary>
    public virtual int TypicalCredentialLength => 256;

    /// <summary>
    /// Performs the get provider key operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="userId">The user id value.</param>
    /// <returns>The operation result.</returns>
    public virtual string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (assertion is ExternalIdentityAssertion externalAssertion)
        {
            return externalAssertion.ProviderKey;
        }

        return string.Empty;
    }

    /// <summary>
    /// Performs the prepare credential value operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="rawValue">The raw value value.</param>
    /// <returns>The operation result.</returns>
    public virtual string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
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

    /// <summary>
    /// Performs the authenticate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

/// <summary>
/// Provides oidc authentication provider behavior.
/// </summary>
/// <param name="providerName">The provider name value.</param>
public sealed class OidcAuthenticationProvider(string providerName) : ExternalAuthenticationProvider(ProviderType.Oidc, providerName)
{
    /// <summary>
    /// Gets or sets the typical credential length value.
    /// </summary>
    public override int TypicalCredentialLength => 512;
}

/// <summary>
/// Provides oauth authentication provider behavior.
/// </summary>
/// <param name="providerName">The provider name value.</param>
public sealed class OAuthAuthenticationProvider(string providerName) : ExternalAuthenticationProvider(ProviderType.OAuth, providerName);

/// <summary>
/// Provides saml2 authentication provider behavior.
/// </summary>
/// <param name="providerName">The provider name value.</param>
public sealed class Saml2AuthenticationProvider(string providerName) : ExternalAuthenticationProvider(ProviderType.Saml2, providerName)
{
    /// <summary>
    /// Gets or sets the typical credential length value.
    /// </summary>
    public override int TypicalCredentialLength => 3072;
}


