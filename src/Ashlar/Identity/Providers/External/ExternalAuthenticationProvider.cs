namespace Ashlar.Identity.Providers.External;

/// <summary>
/// Authenticates identities already validated by host-managed external provider middleware.
/// </summary>
/// <param name="supportedType">External provider family supported by this instance.</param>
/// <param name="providerName">Configured external provider name.</param>
public abstract class ExternalAuthenticationProvider(ProviderType supportedType, string providerName) : IPrimaryAuthenticationProvider, IAuthenticationUserResolver
{
    /// <summary>
    /// Provider key this instance accepts.
    /// </summary>
    public AuthenticationProviderKey Key { get; } = new(supportedType, providerName);

    /// <summary>
    /// Whether stored external credentials should be protected.
    /// </summary>
    public virtual bool ProtectsCredentials => true;

    /// <summary>
    /// Typical storage length for external subject identifiers.
    /// </summary>
    public virtual int TypicalCredentialLength => 256;

    /// <summary>
    /// Extracts the stored credential key from an external identity assertion.
    /// </summary>
    /// <param name="assertion">External identity assertion supplied by the host application.</param>
    /// <param name="userId">User identifier associated with the authentication attempt.</param>
    /// <returns>The external subject identifier, or an empty string when the assertion is unsupported.</returns>
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
    /// Prepares the credential value stored for an external identity.
    /// </summary>
    /// <param name="assertion">External assertion being enrolled or updated.</param>
    /// <param name="rawValue">Provider-specific value to persist, when one is needed.</param>
    /// <returns>The provider-specific credential value to persist, or <see langword="null" /> when no stored value is required. Treat returned values as sensitive unless the provider documents otherwise.</returns>
    public virtual string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        return rawValue;
    }

    /// <summary>
    /// Resolves a user by the external subject identifier.
    /// </summary>
    /// <param name="assertion">External identity assertion supplied by the host application.</param>
    /// <param name="context">Authentication context for the current attempt.</param>
    /// <param name="repository">User repository used to find a matching stored credential.</param>
    /// <param name="cancellationToken">Token for aborting lookup work.</param>
    /// <returns>The matched user, or <see langword="null" /> when no matching external credential exists.</returns>
    public virtual async Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IUserRepository repository, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(repository);

        if (assertion is not ExternalIdentityAssertion externalAssertion)
        {
            return null;
        }

        return await repository.GetUserByProviderKeyAsync(Key.Type, Key.Name, externalAssertion.ProviderKey, cancellationToken);
    }

    /// <summary>
    /// Confirms that the host-validated external assertion matches the stored provider credential.
    /// </summary>
    /// <param name="assertion">External identity assertion already validated by host-managed provider infrastructure.</param>
    /// <param name="credential">Stored external credential to compare against the configured provider identity.</param>
    /// <param name="cancellationToken">Token for aborting authentication work.</param>
    /// <returns>Authentication status and claims copied from the assertion when the provider identity matches.</returns>
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
/// Authenticates host-validated OpenID Connect identities.
/// </summary>
/// <param name="providerName">Configured OpenID Connect provider name.</param>
public sealed class OidcAuthenticationProvider(string providerName) : ExternalAuthenticationProvider(ProviderType.Oidc, providerName)
{
    /// <summary>
    /// Typical storage length for OIDC subject identifiers.
    /// </summary>
    public override int TypicalCredentialLength => 512;
}

/// <summary>
/// Authenticates host-validated OAuth identities.
/// </summary>
/// <param name="providerName">Configured OAuth provider name.</param>
public sealed class OAuthAuthenticationProvider(string providerName) : ExternalAuthenticationProvider(ProviderType.OAuth, providerName);

/// <summary>
/// Authenticates host-validated SAML2 identities.
/// </summary>
/// <param name="providerName">Configured SAML2 provider name.</param>
public sealed class Saml2AuthenticationProvider(string providerName) : ExternalAuthenticationProvider(ProviderType.Saml2, providerName)
{
    /// <summary>
    /// Typical storage length for SAML2 subject identifiers.
    /// </summary>
    public override int TypicalCredentialLength => 3072;
}
