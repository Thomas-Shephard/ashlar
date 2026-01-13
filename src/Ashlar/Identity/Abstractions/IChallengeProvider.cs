namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Generates and tracks cryptographically secure random challenges for authentication protocols like FIDO2.
/// </summary>
public interface IChallengeProvider
{
    /// <summary>
    /// Generates a new challenge and associates it with the specified user or session.
    /// </summary>
    Task<byte[]> GenerateChallengeAsync(Guid? userId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the provided challenge.
    /// </summary>
    Task<bool> ValidateChallengeAsync(byte[] challenge, Guid? userId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a dummy challenge to prevent timing-based user enumeration.
    /// </summary>
    byte[] GetDummyChallenge();
}
