namespace Ashlar.Passkeys;

/// <summary>
/// Defines WebAuthn user verification requirement values accepted by passkey options.
/// </summary>
public static class PasskeyUserVerificationRequirement
{
    /// <summary>
    /// Requires the authenticator to verify the user with a PIN, biometric, device unlock, or equivalent mechanism.
    /// </summary>
    public const string Required = "required";
    /// <summary>
    /// Requests user verification when available while allowing authenticators that only provide user presence.
    /// </summary>
    public const string Preferred = "preferred";
    /// <summary>
    /// Discourages user verification for the ceremony.
    /// </summary>
    public const string Discouraged = "discouraged";
}
