namespace Ashlar.Identity.Models.Totp;

/// <summary>
/// Configuration options for TOTP (Time-based One-Time Password) authentication.
/// </summary>
public sealed class TotpOptions
{
    /// <summary>
    /// The default authentication provider key for TOTP.
    /// </summary>
    public static readonly AuthenticationProviderKey DefaultProviderKey = new(ProviderType.Mfa, "totp");

    /// <summary>
    /// The authentication provider key used for TOTP.
    /// </summary>
    public AuthenticationProviderKey ProviderKey { get; set; } = DefaultProviderKey;

    /// <summary>
    /// The length of the generated shared secret in bytes. Defaults to 20 (160 bits) as per RFC 4226/6238 recommendation.
    /// </summary>
    public int SecretLengthBytes { get; set; } = 20;

    /// <summary>
    /// The number of digits in the TOTP code. Defaults to 6.
    /// </summary>
    public int CodeDigits { get; set; } = 6;

    /// <summary>
    /// The duration of a single TOTP step in seconds. Defaults to 30.
    /// </summary>
    public int StepSeconds { get; set; } = 30;

    /// <summary>
    /// The number of steps (windows) to allow before and after the current time to account for clock skew.
    /// A value of 1 allows one step before and one step after (e.g., +/- 30 seconds if StepSeconds is 30).
    /// Defaults to 1.
    /// </summary>
    public int AllowedSkewSteps { get; set; } = 1;

    /// <summary>
    /// The maximum number of failed TOTP attempts allowed within the rate limit window. Defaults to 5.
    /// </summary>
    public int RateLimitPermitLimit { get; set; } = 5;

    /// <summary>
    /// The window of time for the TOTP rate limiter. Defaults to 5 minutes.
    /// </summary>
    public TimeSpan RateLimitWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Validates TOTP options that are required by enrollment and authentication.
    /// </summary>
    public static bool Validate(TotpOptions options)
    {
        return options is { SecretLengthBytes: > 0, CodeDigits: >= 6 and <= 8, StepSeconds: > 0, AllowedSkewSteps: >= 0, RateLimitPermitLimit: > 0 }
               && options.RateLimitWindow > TimeSpan.Zero
               && options.ProviderKey.Type != default
               && !string.IsNullOrWhiteSpace(options.ProviderKey.Name);
    }

    internal static void ThrowIfInvalid(TotpOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!Validate(options))
        {
            throw new ArgumentException("TOTP options are invalid. SecretLengthBytes, StepSeconds, RateLimitPermitLimit, and RateLimitWindow must be greater than zero; CodeDigits must be between 6 and 8; AllowedSkewSteps cannot be negative; ProviderKey must be initialized.", nameof(options));
        }
    }
}
