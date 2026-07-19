namespace Ashlar.Security.Hashing;

/// <summary>
/// Selects a password hasher by encoded hash version.
/// </summary>
public sealed class PasswordHasherSelector
{
    /// <summary>
    /// Hasher used for new password hashes and unrecognized formats.
    /// </summary>
    public IPasswordHasher DefaultHasher { get; }
    private readonly Dictionary<byte, IPasswordHasher> _hashers = [];

    /// <summary>
    /// Initializes a selector from the available password hashers.
    /// </summary>
    /// <param name="hashers">Hasher implementations keyed by unique version.</param>
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
    /// Gets the hasher that should verify an encoded hash.
    /// </summary>
    /// <param name="encodedHash">The stored encoded hash.</param>
    /// <returns>The matching hasher, or <see cref="DefaultHasher" /> when the version is unknown.</returns>
    public IPasswordHasher GetHasher(ReadOnlySpan<byte> encodedHash)
    {
        if (encodedHash.Length >= IPasswordHasher.VersionLength && _hashers.TryGetValue(encodedHash[0], out var hasher))
        {
            return hasher;
        }

        return DefaultHasher;
    }

    /// <summary>
    /// Verifies a password and reports whether the credential should be upgraded.
    /// </summary>
    /// <param name="password">The plaintext password. Do not log this value.</param>
    /// <param name="encodedHash">The stored encoded hash.</param>
    /// <returns>The verification outcome, including whether a stronger/current hash should replace the stored value.</returns>
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
