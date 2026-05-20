using Microsoft.AspNetCore.DataProtection;

namespace Ashlar.Security.Encryption;

/// <summary>
/// Provides an <see cref="ISecretProtector"/> implementation that uses ASP.NET Core Data Protection
/// to encrypt and decrypt sensitive values.
/// </summary>
/// <remarks>
/// This protector is created with the purpose string <c>"Ashlar.Identity.Features.Credentials"</c> to scope
/// the data protection keys used for credential encryption.
/// </remarks>
public sealed class DataProtectionSecretProtector : ISecretProtector
{
    private readonly IDataProtector _protector;

    /// <summary>
    /// Initializes a new instance of the data protection secret protector class.
    /// </summary>
    /// <param name="provider">The provider value.</param>
    public DataProtectionSecretProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector("Ashlar.Identity.Features.Credentials");
    }

    /// <summary>
    /// Performs the protect operation and returns the result.
    /// </summary>
    /// <param name="data">The data value.</param>
    /// <returns>The operation result.</returns>
    public byte[] Protect(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return _protector.Protect(data);
    }

    /// <summary>
    /// Performs the unprotect operation and returns the result.
    /// </summary>
    /// <param name="data">The data value.</param>
    /// <returns>The operation result.</returns>
    public byte[] Unprotect(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return _protector.Unprotect(data);
    }
}
