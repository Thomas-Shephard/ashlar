using System.Diagnostics.CodeAnalysis;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

public sealed class AuthenticationProviderRegistry : IAuthenticationProviderRegistry
{
    private readonly IReadOnlyDictionary<ProviderType, IAuthenticationProvider> _providers;

    public AuthenticationProviderRegistry(IEnumerable<IAuthenticationProvider> providers)
    {
        var dict = new Dictionary<ProviderType, IAuthenticationProvider>();

        foreach (var provider in providers ?? throw new ArgumentNullException(nameof(providers)))
        {
            ArgumentNullException.ThrowIfNull(provider);

            if (!dict.TryAdd(provider.SupportedType, provider))
            {
                throw new ArgumentException("Duplicate provider registered for type", nameof(providers));
            }
        }

        _providers = dict;
    }

    public IEnumerable<ProviderType> SupportedProviderTypes => _providers.Keys;

    public bool TryGetProvider(IAuthenticationAssertion assertion, AuthenticationContext context, [NotNullWhen(true)] out IAuthenticationProvider? provider)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(context);

        return _providers.TryGetValue(assertion.ProviderType, out provider);
    }
}
