using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Identity.Features.Authentication;

/// <summary>
/// Resolves registered authentication providers by assertion or provider key.
/// </summary>
public sealed class AuthenticationProviderRegistry : IAuthenticationProviderRegistry
{
    private readonly IReadOnlyDictionary<AuthenticationProviderKey, IAuthenticationProvider> _providers;

    /// <summary>
    /// Initializes a registry from the configured provider collection.
    /// </summary>
    /// <param name="providers">Authentication providers registered in dependency injection.</param>
    public AuthenticationProviderRegistry(IEnumerable<IAuthenticationProvider> providers)
    {
        var dict = new Dictionary<AuthenticationProviderKey, IAuthenticationProvider>();

        foreach (var provider in providers ?? throw new ArgumentNullException(nameof(providers)))
        {
            ArgumentNullException.ThrowIfNull(provider);

            var key = ValidateProviderKey(provider.Key, nameof(providers));
            ValidateSecondaryFactorProvider(provider, nameof(providers));
            if (!dict.TryAdd(key, provider))
            {
                throw new ArgumentException($"Duplicate provider registered for key '{key}'.", nameof(providers));
            }
        }

        _providers = dict;
    }

    /// <summary>
    /// Gets the provider keys registered in this registry.
    /// </summary>
    public IEnumerable<AuthenticationProviderKey> SupportedProviderKeys => _providers.Keys;

    /// <summary>
    /// Attempts to resolve the provider that can validate an assertion.
    /// </summary>
    /// <param name="assertion">Authentication assertion submitted by the caller.</param>
    /// <param name="provider">Resolved provider when the assertion is supported.</param>
    /// <returns><see langword="true" /> when a matching provider is registered.</returns>
    public bool TryGetProvider(IAuthenticationAssertion assertion, [NotNullWhen(true)] out IAuthenticationProvider? provider)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        return TryGetProvider(assertion.ProviderIdentity, out provider);
    }

    /// <summary>
    /// Attempts to resolve a provider by its canonical provider key.
    /// </summary>
    /// <param name="providerKey">The provider key.</param>
    /// <param name="provider">Resolved provider when the key is registered.</param>
    /// <returns><see langword="true" /> when a matching provider is registered.</returns>
    public bool TryGetProvider(AuthenticationProviderKey providerKey, [NotNullWhen(true)] out IAuthenticationProvider? provider)
    {
        return _providers.TryGetValue(providerKey, out provider);
    }

    private static AuthenticationProviderKey ValidateProviderKey(AuthenticationProviderKey key, string parameterName)
    {
        AuthenticationProviderKey.ThrowIfNotConfigured(key, parameterName);
        return key;
    }

    private static void ValidateSecondaryFactorProvider(IAuthenticationProvider provider, string parameterName)
    {
        if (provider is ISecondaryAuthenticationFactorProvider factorProvider &&
            string.IsNullOrWhiteSpace(factorProvider.FactorType))
        {
            throw new ArgumentException("Secondary factor provider must declare a factor type.", parameterName);
        }
    }
}
