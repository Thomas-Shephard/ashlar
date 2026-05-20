namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Defines the contract for iemail verification service operations.
/// </summary>
public interface IEmailVerificationService
{
    /// <summary>
    /// Performs the request verification <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> RequestVerificationAsync(EmailVerificationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the confirm verification <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> ConfirmVerificationAsync(ConfirmEmailVerificationRequest request, CancellationToken cancellationToken = default);
}
