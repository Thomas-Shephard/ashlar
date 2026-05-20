using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Identity.Features.Authentication;

/// <summary>
/// Provides authentication provider registry behavior.
/// </summary>
public sealed class AuthenticationProviderRegistry : IAuthenticationProviderRegistry
{
    private readonly IReadOnlyDictionary<AuthenticationProviderKey, IAuthenticationProvider> _providers;

    /// <summary>
    /// Initializes a new instance of the authentication provider registry class.
    /// </summary>
    /// <param name="providers">The providers value.</param>
    public AuthenticationProviderRegistry(IEnumerable<IAuthenticationProvider> providers)
    {
        var dict = new Dictionary<AuthenticationProviderKey, IAuthenticationProvider>();

        foreach (var provider in providers ?? throw new ArgumentNullException(nameof(providers)))
        {
            ArgumentNullException.ThrowIfNull(provider);

            var key = ValidateProviderKey(provider.Key, nameof(providers));
            if (!dict.TryAdd(key, provider))
            {
                throw new ArgumentException($"Duplicate provider registered for key '{key}'.", nameof(providers));
            }
        }

        _providers = dict;
    }

    /// <summary>
    /// Gets or sets the supported provider keys value.
    /// </summary>
    public IEnumerable<AuthenticationProviderKey> SupportedProviderKeys => _providers.Keys;

    /// <summary>
    /// Performs the try get provider operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="provider">The provider value.</param>
    /// <returns>The operation result.</returns>
    public bool TryGetProvider(IAuthenticationAssertion assertion, [NotNullWhen(true)] out IAuthenticationProvider? provider)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        return _providers.TryGetValue(assertion.ProviderIdentity, out provider);
    }

    private static AuthenticationProviderKey ValidateProviderKey(AuthenticationProviderKey key, string parameterName)
    {
        if (key.Type == default || string.IsNullOrWhiteSpace(key.Name))
        {
            throw new ArgumentException("Provider key must be fully initialized with a type and name.", parameterName);
        }

        return key;
    }
}
