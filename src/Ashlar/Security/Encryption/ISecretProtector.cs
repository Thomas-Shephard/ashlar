using System.Security.Cryptography;
using System.Text;

namespace Ashlar.Security.Encryption;

/// <summary>
/// Provides methods for reversible protection of sensitive data.
/// </summary>
public interface ISecretProtector
{
    /// <summary>
    /// Protects the specified data.
    /// </summary>
    /// <param name="data">The data to protect.</param>
    /// <returns>The protected data.</returns>
    byte[] Protect(byte[] data);

    /// <summary>
    /// Protects the specified plain text.
    /// </summary>
    /// <param name="plainText">The text to protect.</param>
    /// <returns>The protected cipher text (Base64 encoded).</returns>
    string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);
        var plaintextBytes = Encoding.UTF8.GetBytes(plainText);
        var protectedBytes = Protect(plaintextBytes);
        return Convert.ToBase64String(protectedBytes);
    }

    /// <summary>
    /// Unprotects the specified data.
    /// </summary>
    /// <param name="data">The protected data.</param>
    /// <returns>The original data.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the data is malformed or decryption fails.</exception>
    byte[] Unprotect(byte[] data);

    /// <summary>
    /// Unprotects the specified cipher text.
    /// </summary>
    /// <param name="cipherText">The protected cipher text (Base64 encoded).</param>
    /// <returns>The original plain text.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the cipher text is malformed or decryption fails.</exception>
    string Unprotect(string cipherText)
    {
        if (string.IsNullOrWhiteSpace(cipherText))
        {
            throw new CryptographicException("The cipher text cannot be empty.");
        }

        byte[] protectedBytes;
        try
        {
            protectedBytes = Convert.FromBase64String(cipherText);
        }
        catch (FormatException ex)
        {
            throw new CryptographicException("The cipher text is not a valid Base64 string.", ex);
        }

        var unprotectedBytes = Unprotect(protectedBytes);
        return Encoding.UTF8.GetString(unprotectedBytes);
    }
}
