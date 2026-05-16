using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

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
    /// Performs the verify token <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="token">The token value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> VerifyTokenAsync(Guid userId, string token, CancellationToken cancellationToken = default);
}
