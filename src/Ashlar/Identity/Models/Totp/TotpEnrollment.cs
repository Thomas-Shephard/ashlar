namespace Ashlar.Identity.Models.Totp;

/// <summary>
/// Represents the result of starting a TOTP enrollment process.
/// </summary>
/// <param name="SharedSecret">The shared secret value.</param>
/// <param name="AuthenticatorUri">The authenticator uri value.</param>
public sealed record TotpEnrollment(
    string SharedSecret,
    string AuthenticatorUri);
