namespace Ashlar.Security.Encryption;

/// <summary>
/// Provides methods for reversible protection of sensitive data.
/// </summary>
public interface ISecretProtector
{
    /// <summary>
    /// Protects the specified plain text.
    /// </summary>
    /// <param name="plainText">The text to protect.</param>
    /// <returns>The protected cipher text.</returns>
    string Protect(string plainText);

    /// <summary>
    /// Unprotects the specified cipher text.
    /// </summary>
    /// <param name="cipherText">The protected cipher text.</param>
    /// <returns>The original plain text.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the cipher text is malformed or decryption fails.</exception>
    string Unprotect(string cipherText);
}
