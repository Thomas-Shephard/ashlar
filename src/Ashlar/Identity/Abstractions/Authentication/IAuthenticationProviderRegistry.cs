using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Low-level registry used by authentication infrastructure to resolve providers for assertions and provider keys.
/// </summary>
public interface IAuthenticationProviderRegistry
{
    /// <summary>
    /// Gets the provider keys registered in the current service provider.
    /// </summary>
    IEnumerable<AuthenticationProviderKey> SupportedProviderKeys { get; }

    /// <summary>
    /// Attempts to resolve the provider that can validate an assertion.
    /// </summary>
    /// <param name="assertion">Authentication assertion submitted by the caller.</param>
    /// <param name="provider">Resolved provider when the assertion is supported.</param>
    /// <returns><see langword="true" /> when a matching provider is registered.</returns>
    bool TryGetProvider(IAuthenticationAssertion assertion, [NotNullWhen(true)] out IAuthenticationProvider? provider);

    /// <summary>
    /// Attempts to resolve a provider by its canonical provider key.
    /// </summary>
    /// <param name="providerKey">The provider key.</param>
    /// <param name="provider">Resolved provider when the key is registered.</param>
    /// <returns><see langword="true" /> when a matching provider is registered.</returns>
    bool TryGetProvider(AuthenticationProviderKey providerKey, [NotNullWhen(true)] out IAuthenticationProvider? provider);
}
