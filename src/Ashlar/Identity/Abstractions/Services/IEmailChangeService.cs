
namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Defines the contract for iemail change service operations.
/// </summary>
public interface IEmailChangeService
{
    /// <summary>
    /// Performs the request change <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> RequestChangeAsync(RequestEmailChangeRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the confirm change <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> ConfirmChangeAsync(ConfirmEmailChangeRequest request, CancellationToken cancellationToken = default);
}





