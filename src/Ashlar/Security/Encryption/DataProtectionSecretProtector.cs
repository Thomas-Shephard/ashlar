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

    public byte[] Protect(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return _protector.Protect(data);
    }

    public byte[] Unprotect(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return _protector.Unprotect(data);
    }
}
