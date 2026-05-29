namespace Ashlar.Identity.Models.Mfa;

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

    /// <summary>
    /// Determines whether two factor type values represent the same factor family.
    /// </summary>
    /// <param name="left">The first factor type value.</param>
    /// <param name="right">The second factor type value.</param>
    /// <returns><see langword="true" /> when the factor type values match.</returns>
    public static bool Matches(string? left, string? right)
    {
        return StringComparer.OrdinalIgnoreCase.Equals(left, right) ||
            Normalize(left) == Normalize(right);
    }

    private static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = string.Concat(value.Where(char.IsLetterOrDigit)).ToUpperInvariant();
        return string.IsNullOrEmpty(normalized) ? value.ToUpperInvariant() : normalized;
    }
}
