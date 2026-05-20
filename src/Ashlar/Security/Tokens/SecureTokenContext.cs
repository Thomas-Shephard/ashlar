namespace Ashlar.Security.Tokens;

/// <summary>
/// Groups secure token generation and hashing dependencies.
/// </summary>
/// <param name="generator">The generator value.</param>
/// <param name="hasher">The hasher value.</param>
public sealed class SecureTokenContext(
    ISecureTokenGenerator generator,
    ISecureTokenHasher hasher)
{
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public ISecureTokenGenerator Generator { get; } = generator ?? throw new ArgumentNullException(nameof(generator));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public ISecureTokenHasher Hasher { get; } = hasher ?? throw new ArgumentNullException(nameof(hasher));
}


