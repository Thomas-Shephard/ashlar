using System.Diagnostics.CodeAnalysis;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationProviderRegistry
{
    IEnumerable<ProviderType> SupportedProviderTypes { get; }

    bool TryGetProvider(IAuthenticationAssertion assertion, AuthenticationContext context, [NotNullWhen(true)] out IAuthenticationProvider? provider);
}
