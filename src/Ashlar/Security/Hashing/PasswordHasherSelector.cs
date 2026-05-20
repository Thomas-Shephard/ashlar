namespace Ashlar.Security.Hashing;

/// <summary>
/// Provides password hasher selector behavior.
/// </summary>
public sealed class PasswordHasherSelector
{
    /// <summary>
    /// Gets or sets the default hasher value.
    /// </summary>
    public IPasswordHasher DefaultHasher { get; }
    private readonly Dictionary<byte, IPasswordHasher> _hashers = [];

    /// <summary>
    /// Initializes a new instance of the password hasher selector class.
    /// </summary>
    /// <param name="hashers">The hashers value.</param>
    public PasswordHasherSelector(IEnumerable<IPasswordHasher> hashers)
    {
        ArgumentNullException.ThrowIfNull(hashers);

        IPasswordHasher? defaultHasher = null;
        foreach (var hasher in hashers)
        {
            ArgumentNullException.ThrowIfNull(hasher);

            if (!_hashers.TryAdd(hasher.Version, hasher))
            {
                throw new ArgumentException($"Duplicate password hasher version: {hasher.Version}", nameof(hashers));
            }

            if (defaultHasher == null || hasher.Version > defaultHasher.Version)
            {
                defaultHasher = hasher;
            }
        }

        DefaultHasher = defaultHasher ?? throw new ArgumentException("At least one password hasher must be provided.", nameof(hashers));
    }

    /// <summary>
    /// Performs the get hasher operation and returns the result.
    /// </summary>
    /// <param name="encodedHash">The encoded hash value.</param>
    /// <returns>The operation result.</returns>
    public IPasswordHasher GetHasher(ReadOnlySpan<byte> encodedHash)
    {
        if (encodedHash.Length >= IPasswordHasher.VersionLength && _hashers.TryGetValue(encodedHash[0], out var hasher))
        {
            return hasher;
        }

        return DefaultHasher;
    }

    /// <summary>
    /// Performs the verify password operation and returns the result.
    /// </summary>
    /// <param name="password">The password value.</param>
    /// <param name="encodedHash">The encoded hash value.</param>
    /// <returns>The operation result.</returns>
    public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> encodedHash)
    {
        var hasher = GetHasher(encodedHash);

        if (!hasher.VerifyPassword(password, encodedHash))
        {
            return PasswordVerificationResult.Failed;
        }

        return hasher.Version == DefaultHasher.Version
            ? PasswordVerificationResult.Success
            : PasswordVerificationResult.SuccessWithCredentialUpdate;
    }
}
