namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Options for recovery code generation and authentication.
/// </summary>
public sealed record RecoveryCodeOptions
{
    /// <summary>
    /// Number of recovery codes to generate. Defaults to 10.
    /// </summary>
    public int CodeCount { get; set; } = 10;

    /// <summary>
    /// Length of the secret portion of each recovery code, excluding the ID prefix and group separators. Defaults to 12.
    /// </summary>
    public int CodeLength { get; set; } = 12;

    /// <summary>
    /// Size of each character group in the recovery code. Defaults to 4.
    /// </summary>
    public int GroupSize { get; set; } = 4;

    /// <summary>
    /// Duration after which recovery codes expire.
    /// </summary>
    public TimeSpan? ExpiresAfter { get; set; }

    /// <summary>
    /// Authentication provider key used for recovery-code credentials.
    /// </summary>
    public AuthenticationProviderKey ProviderKey { get; set; } = new(ProviderType.RecoveryCode, "RecoveryCode");

    /// <summary>
    /// Validates recovery code options.
    /// </summary>
    /// <param name="options">Recovery-code settings to validate.</param>
    /// <returns><see langword="true" /> when recovery codes can be generated and verified with the supplied settings.</returns>
    public static bool Validate(RecoveryCodeOptions? options)
    {
        if (options == null)
        {
            return false;
        }

        if (options.CodeCount <= 0 || options.CodeLength <= 0 || options.GroupSize <= 0)
        {
            return false;
        }

        if (options.ProviderKey.Type == default)
        {
            return false;
        }

        if (options.ExpiresAfter.HasValue && options.ExpiresAfter.Value <= TimeSpan.Zero)
        {
            return false;
        }

        return true;
    }
}
