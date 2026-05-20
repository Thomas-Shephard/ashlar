using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers;

internal static class PasswordCredentialHashing
{
    /// <summary>
    /// Performs the hash to base64 operation and returns the result.
    /// </summary>
    /// <param name="hasherSelector">The hasher selector value.</param>
    /// <param name="rawValue">The raw value value.</param>
    /// <returns>The operation result.</returns>
    public static string HashToBase64(PasswordHasherSelector hasherSelector, string rawValue)
    {
        return Convert.ToBase64String(hasherSelector.DefaultHasher.HashPassword(rawValue));
    }

    /// <summary>
    /// Performs the decode base64 operation and returns the result.
    /// </summary>
    /// <param name="credentialValue">The credential value value.</param>
    /// <returns>The operation result.</returns>
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
