using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Defines the contract for iemail code sign in service operations.
/// </summary>
public interface IEmailCodeSignInService
{
    /// <summary>
    /// Performs the request code <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task RequestCodeAsync(string email, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the verify code <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="code">The code value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationResponse> VerifyCodeAsync(string email, string code, AuthenticationContext? context = null, CancellationToken cancellationToken = default);
}
