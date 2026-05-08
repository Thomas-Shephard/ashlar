namespace Ashlar.Identity.Models.Totp;

/// <summary>
/// Represents the result of starting a TOTP enrollment process.
/// </summary>
public sealed record TotpEnrollment(
    string SharedSecret,
    string AuthenticatorUri);
