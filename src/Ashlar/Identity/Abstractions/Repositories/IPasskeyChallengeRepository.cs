using Ashlar.Identity.Models.Passkeys;

namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Persists short-lived passkey registration and authentication challenges.
/// </summary>
public interface IPasskeyChallengeRepository
{
    /// <summary>
    /// Stores a passkey challenge.
    /// </summary>
    /// <param name="challenge">The challenge to store.</param>
    /// <param name="cancellationToken">A token that can cancel challenge persistence.</param>
    Task CreateAsync(PasskeyChallenge challenge, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a challenge by id. Callers are responsible for validating consumed and expiry state.
    /// </summary>
    /// <param name="id">The public challenge identifier to load.</param>
    /// <param name="cancellationToken">A token that can cancel challenge lookup.</param>
    /// <returns>The challenge when found; otherwise, <see langword="null" />.</returns>
    Task<PasskeyChallenge?> GetAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically marks a challenge consumed when the expected version still matches.
    /// </summary>
    /// <param name="id">The public challenge identifier to consume.</param>
    /// <param name="expectedVersion">The version observed before the consume attempt.</param>
    /// <param name="consumedAt">UTC time observed by the application when the ceremony completed.</param>
    /// <param name="cancellationToken">A token that can cancel challenge consumption.</param>
    /// <returns><see langword="true" /> when the challenge was consumed.</returns>
    /// <remarks>
    /// Implementations must atomically verify the expected version, unconsumed state, and unexpired state using
    /// a consistent clock source for the provider. The persisted consumption timestamp may come from either the
    /// supplied value or the provider clock, but replay prevention must not depend on caller-side checks alone.
    /// </remarks>
    Task<bool> ConsumeAsync(Guid id, string expectedVersion, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);
}
