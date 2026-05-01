using System.Diagnostics.CodeAnalysis;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

public sealed class AuthenticationProviderRegistry : IAuthenticationProviderRegistry
{
    private readonly IReadOnlyDictionary<AuthenticationProviderKey, IAuthenticationProvider> _providers;

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

    public IEnumerable<AuthenticationProviderKey> SupportedProviderKeys => _providers.Keys;

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
