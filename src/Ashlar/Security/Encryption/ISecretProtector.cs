using System.Security.Cryptography;
using System.Text;

namespace Ashlar.Security.Encryption;

/// <summary>
/// Provides methods for reversible protection of sensitive data.
/// </summary>
public interface ISecretProtector
{
    /// <summary>
    /// Protects plaintext bytes for reversible storage.
    /// </summary>
    /// <param name="data">The plaintext bytes to protect. Treat this value as sensitive.</param>
    /// <returns>Protected bytes suitable for persistence by the configured protector.</returns>
    byte[] Protect(byte[] data);

    /// <summary>
    /// Protects UTF-8 <paramref name="plainText" /> and returns a Base64 encoded protected payload.
    /// </summary>
    /// <param name="plainText">The <paramref name="plainText" /> to protect. Treat this value as sensitive.</param>
    /// <returns>A Base64 encoded protected payload suitable for persistence.</returns>
    string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);
        var plaintextBytes = Encoding.UTF8.GetBytes(plainText);
        var protectedBytes = Protect(plaintextBytes);
        return Convert.ToBase64String(protectedBytes);
    }

    /// <summary>
    /// Decrypts or unprotects a protected byte payload.
    /// </summary>
    /// <param name="data">The protected bytes previously returned by <see cref="Protect(byte[])" />.</param>
    /// <returns>The original plaintext bytes. Treat the returned value as sensitive.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the data is malformed or decryption fails.</exception>
    byte[] Unprotect(byte[] data);

    /// <summary>
    /// Decodes and unprotects a Base64 protected payload.
    /// </summary>
    /// <param name="cipherText">Base64 encoded protected payload to decode and unprotect.</param>
    /// <returns>The original plaintext. Treat the returned value as sensitive.</returns>
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
