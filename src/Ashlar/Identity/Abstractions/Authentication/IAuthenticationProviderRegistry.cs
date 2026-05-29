using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Defines the contract for authentication provider registry operations.
/// </summary>
public interface IAuthenticationProviderRegistry
{
    /// <summary>
    /// Gets the supported provider keys value.
    /// </summary>
    IEnumerable<AuthenticationProviderKey> SupportedProviderKeys { get; }

    /// <summary>
    /// Performs the try get provider operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="provider">The provider value.</param>
    /// <returns>The operation result.</returns>
    bool TryGetProvider(IAuthenticationAssertion assertion, [NotNullWhen(true)] out IAuthenticationProvider? provider);

    /// <summary>
    /// Performs the try get provider operation by canonical provider key and returns the result.
    /// </summary>
    /// <param name="providerKey">The provider key.</param>
    /// <param name="provider">The provider value.</param>
    /// <returns>The operation result.</returns>
    bool TryGetProvider(AuthenticationProviderKey providerKey, [NotNullWhen(true)] out IAuthenticationProvider? provider);
}
