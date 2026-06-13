using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers;

internal static class PasswordCredentialHashing
{
    /// <summary>
    /// Hashes a raw credential value and encodes the hash for storage.
    /// </summary>
    /// <param name="hasherSelector">Hasher selector that supplies the current default hasher.</param>
    /// <param name="rawValue">Raw credential value. Do not log this value.</param>
    /// <returns>Base64-encoded password-hash payload for persistence.</returns>
    public static string HashToBase64(PasswordHasherSelector hasherSelector, string rawValue)
    {
        return Convert.ToBase64String(hasherSelector.DefaultHasher.HashPassword(rawValue));
    }

    /// <summary>
    /// Decodes a persisted credential hash payload.
    /// </summary>
    /// <param name="credentialValue">Base64-encoded credential hash payload from storage.</param>
    /// <returns>Decoded hash bytes, or <see langword="null" /> when no valid payload was supplied.</returns>
    public static byte[]? DecodeBase64(string? credentialValue)
    {
        if (credentialValue == null)
        {
            return null;
        }

        try
        {
            return Convert.FromBase64String(credentialValue);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
