using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Defines the contract for imagic link sign in service operations.
/// </summary>
public interface IMagicLinkSignInService
{
    /// <summary>
    /// Performs the request link <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="callbackBaseUri">The callback base uri value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task RequestLinkAsync(string email, Uri callbackBaseUri, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the verify link <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="token">The token value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationResponse> VerifyLinkAsync(string token, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
