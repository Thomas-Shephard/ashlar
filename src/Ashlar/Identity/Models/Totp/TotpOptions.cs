namespace Ashlar.Identity.Models.Totp;

/// <summary>
/// Configuration options for TOTP (Time-based One-Time Password) authentication.
/// </summary>
public sealed class TotpOptions
{
    /// <summary>
    /// Default authentication provider key for TOTP credentials.
    /// </summary>
    public static readonly AuthenticationProviderKey DefaultProviderKey = new(ProviderType.Mfa, "totp");

    /// <summary>
    /// Authentication provider key used for TOTP credentials.
    /// </summary>
    public AuthenticationProviderKey ProviderKey { get; set; } = DefaultProviderKey;

    /// <summary>
    /// Generated shared-secret length in bytes.
    /// </summary>
    public int SecretLengthBytes { get; set; } = 20;

    /// <summary>
    /// Number of digits expected in TOTP codes.
    /// </summary>
    public int CodeDigits { get; set; } = 6;

    /// <summary>
    /// Duration of a single TOTP time step in seconds.
    /// </summary>
    public int StepSeconds { get; set; } = 30;

    /// <summary>
    /// Number of time steps accepted before and after the current step.
    /// </summary>
    public int AllowedSkewSteps { get; set; } = 1;

    /// <summary>
    /// Validates TOTP options that are required by enrollment and authentication.
    /// </summary>
    /// <param name="options">Options instance to validate.</param>
    /// <returns><see langword="true" /> when enrollment and authentication can use the supplied settings; otherwise, <see langword="false" />.</returns>
    public static bool Validate(TotpOptions options)
    {
        return options is { SecretLengthBytes: > 0, CodeDigits: >= 6 and <= 8, StepSeconds: > 0, AllowedSkewSteps: >= 0 }
               && options.ProviderKey.Type != default
               && !string.IsNullOrWhiteSpace(options.ProviderKey.Name);
    }

    internal static void ThrowIfInvalid(TotpOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!Validate(options))
        {
            throw new ArgumentException("TOTP options are invalid. SecretLengthBytes and StepSeconds must be valid; CodeDigits must be between 6 and 8; AllowedSkewSteps cannot be negative; ProviderKey must be initialized.", nameof(options));
        }
    }
}
