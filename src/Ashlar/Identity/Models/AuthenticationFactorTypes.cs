namespace Ashlar.Identity.Models;

/// <summary>
/// Well-known Ashlar authentication factor type values.
/// </summary>
public static class AuthenticationFactorTypes
{
    /// <summary>
    /// Authenticator app one-time password verification.
    /// </summary>
    public const string Totp = "totp";

    /// <summary>
    /// Recovery code verification.
    /// </summary>
    public const string RecoveryCode = "recovery_code";

    /// <summary>
    /// Passkey/WebAuthn verification.
    /// </summary>
    public const string Passkey = "passkey";
}
