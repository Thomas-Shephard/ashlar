namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Persists short-lived authentication handshakes used for MFA and step-up flows.
/// </summary>
public interface IAuthenticationHandshakeRepository
{
    /// <summary>
    /// Stores a newly issued handshake.
    /// </summary>
    /// <param name="handshake">Handshake record to persist. It contains only a token hash, not the raw token.</param>
    /// <param name="cancellationToken">A token that can cancel persistence.</param>
    /// <returns>A task that completes when the handshake has been stored.</returns>
    Task CreateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default);
    /// <summary>
    /// Finds a handshake by its storage-safe token hash.
    /// </summary>
    /// <param name="tokenHash">Storage-safe hash of the raw handshake token presented by a caller.</param>
    /// <param name="forUpdate">When <see langword="true" />, requests an exclusive read suitable for a subsequent state change.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The matching handshake, or <see langword="null" /> when none exists.</returns>
    /// <remarks>
    /// This is a provider-neutral lock intent. Relational providers may implement it with row-level locking,
    /// optimistic version checks, or an equivalent single-writer strategy appropriate to the backing store.
    /// </remarks>
    Task<AuthenticationHandshake?> FindByTokenHashAsync(string tokenHash, bool forUpdate = false, CancellationToken cancellationToken = default);
    /// <summary>
    /// Updates handshake state after verification, completion, or revocation.
    /// </summary>
    /// <param name="handshake">Updated handshake record to persist.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns><see langword="true" /> when the handshake was updated; otherwise, <see langword="false" />.</returns>
    Task<bool> UpdateAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken = default);
}
