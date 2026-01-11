using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace Ashlar.Security.Encryption;

/// <summary>
/// Provides an <see cref="ISecretProtector"/> implementation that uses ASP.NET Core Data Protection
/// to encrypt and decrypt sensitive values.
/// </summary>
/// <remarks>
/// This protector is created with the purpose string <c>"Ashlar.Identity.Credentials"</c> to scope
/// the data protection keys used for credential encryption.
/// </remarks>
public sealed class DataProtectionSecretProtector : ISecretProtector
{
    private readonly IDataProtector _protector;

    public DataProtectionSecretProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector("Ashlar.Identity.Credentials");
    }

    public string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);
        var plaintextBytes = Encoding.UTF8.GetBytes(plainText);
        var protectedBytes = _protector.Protect(plaintextBytes);
        return Convert.ToBase64String(protectedBytes);
    }

    public string Unprotect(string cipherText)
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

        var unprotectedBytes = _protector.Unprotect(protectedBytes);
        return Encoding.UTF8.GetString(unprotectedBytes);
    }
}
