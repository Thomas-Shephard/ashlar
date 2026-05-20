
namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Defines the contract for authentication pipeline operations.
/// </summary>
public interface IAuthenticationPipeline
{
    /// <summary>
    /// Performs the login <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="context">The context value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default);
}





