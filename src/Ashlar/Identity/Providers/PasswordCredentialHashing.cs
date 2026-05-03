using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers;

internal static class PasswordCredentialHashing
{
    public static string HashToBase64(PasswordHasherSelector hasherSelector, string rawValue)
    {
        return Convert.ToBase64String(hasherSelector.DefaultHasher.HashPassword(rawValue));
    }

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
