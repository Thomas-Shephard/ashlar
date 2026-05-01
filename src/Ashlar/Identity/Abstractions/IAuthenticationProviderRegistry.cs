using System.Diagnostics.CodeAnalysis;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationProviderRegistry
{
    IEnumerable<AuthenticationProviderKey> SupportedProviderKeys { get; }

    bool TryGetProvider(IAuthenticationAssertion assertion, [NotNullWhen(true)] out IAuthenticationProvider? provider);
}
