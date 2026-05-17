using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Defines the contract for authentication handshake repository operations.
/// </summary>
public interface IAuthenticationHandshakeRepository
{
    /// <summary>
    /// Performs the create <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="handshake">The handshake value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task CreateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the find by token hash <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="tokenHash">The token hash value.</param>
    /// <param name="forUpdate">When <see langword="true" />, requests an exclusive read suitable for a subsequent state change.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// This is a provider-neutral lock intent. Relational providers may implement it with row-level locking,
    /// optimistic version checks, or an equivalent single-writer strategy appropriate to the backing store.
    /// </remarks>
    Task<AuthenticationHandshake?> FindByTokenHashAsync(string tokenHash, bool forUpdate = false, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the update <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="handshake">The handshake value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task UpdateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default);
}
