namespace Ashlar.Security.Tokens;

/// <summary>
/// Groups secure token generation and hashing dependencies.
/// </summary>
/// <param name="generator">Generates raw bearer tokens.</param>
/// <param name="hasher">Hashes raw tokens before storage.</param>
public sealed class SecureTokenContext(
    ISecureTokenGenerator generator,
    ISecureTokenHasher hasher)
{
    /// <summary>
    /// Token generator used to issue raw bearer values.
    /// </summary>
    public ISecureTokenGenerator Generator { get; } = generator ?? throw new ArgumentNullException(nameof(generator));
    /// <summary>
    /// Token hasher used before token values are stored.
    /// </summary>
    public ISecureTokenHasher Hasher { get; } = hasher ?? throw new ArgumentNullException(nameof(hasher));
}
