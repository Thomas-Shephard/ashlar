namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Defines the contract for authentication pipeline operations.
/// </summary>
public interface IAuthenticationPipeline
{
    /// <summary>
    /// Performs primary sign-in authentication and returns the result.
    /// </summary>
    /// <param name="context">The context value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationResponse> LoginAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Defines the contract for secondary factor authentication pipeline operations.
/// </summary>
public interface IAuthenticationFactorPipeline
{
    /// <summary>
    /// Verifies a secondary authentication factor without applying primary sign-in throttles.
    /// </summary>
    /// <param name="context">The context value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationResponse> VerifyFactorAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default);
}
