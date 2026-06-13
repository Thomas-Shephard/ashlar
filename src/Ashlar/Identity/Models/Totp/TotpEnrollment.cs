namespace Ashlar.Identity.Models.Totp;

/// <summary>
/// Contains the secret material needed to complete TOTP enrollment.
/// </summary>
/// <param name="SharedSecret">Raw shared secret for the authenticator app. Show it only during enrollment and do not log it.</param>
/// <param name="AuthenticatorUri">Provisioning URI for authenticator apps. Treat it as sensitive because it embeds the shared secret.</param>
public sealed record TotpEnrollment(
    string SharedSecret,
    string AuthenticatorUri);
