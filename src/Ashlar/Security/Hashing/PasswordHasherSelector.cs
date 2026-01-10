namespace Ashlar.Security.Hashing;

public sealed class PasswordHasherSelector
{
    public IPasswordHasher DefaultHasher { get; }
    private readonly Dictionary<byte, IPasswordHasher> _hashers = [];

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

    public IPasswordHasher GetHasher(ReadOnlySpan<byte> encodedHash)
    {
        if (encodedHash.Length >= IPasswordHasher.VersionLength && _hashers.TryGetValue(encodedHash[0], out var hasher))
        {
            return hasher;
        }

        return DefaultHasher;
    }

    public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> encodedHash)
    {
        var hasher = GetHasher(encodedHash);

        if (!hasher.VerifyPassword(password, encodedHash))
        {
            return PasswordVerificationResult.Failed;
        }

        return hasher.Version == DefaultHasher.Version
            ? PasswordVerificationResult.Success
            : PasswordVerificationResult.SuccessRehashNeeded;
    }
}
