namespace Ashlar.Security.Tokens;

/// <summary>
/// Groups secure token generation and hashing dependencies.
/// </summary>
public sealed class SecureTokenContext(
    ISecureTokenGenerator generator,
    ISecureTokenHasher hasher)
{
    public ISecureTokenGenerator Generator { get; } = generator ?? throw new ArgumentNullException(nameof(generator));
    public ISecureTokenHasher Hasher { get; } = hasher ?? throw new ArgumentNullException(nameof(hasher));
}
