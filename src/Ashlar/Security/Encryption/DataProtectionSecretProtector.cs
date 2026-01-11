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
        return _protector.Protect(plainText);
    }

    public string Unprotect(string cipherText)
    {
        ArgumentNullException.ThrowIfNull(cipherText);
        try
        {
            return _protector.Unprotect(cipherText);
        }
        catch (FormatException ex)
        {
            throw new System.Security.Cryptography.CryptographicException("The cipher text is not a valid Base64 string.", ex);
        }
    }
}
