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
    /// <param name="forUpdate">The for update value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationHandshake?> FindByTokenHashAsync(string tokenHash, bool forUpdate = false, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the update <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="handshake">The handshake value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task UpdateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default);
}
