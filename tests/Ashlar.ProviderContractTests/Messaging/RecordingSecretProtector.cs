using System.Security.Cryptography;
using Ashlar.Security.Encryption;

namespace Ashlar.ProviderContractTests.Messaging;

internal sealed class RecordingSecretProtector : ISecretProtector
{
    private static readonly byte[] Prefix = "protected:"u8.ToArray();

    public byte[] Protect(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        var protectedData = new byte[Prefix.Length + data.Length];
        Buffer.BlockCopy(Prefix, 0, protectedData, 0, Prefix.Length);
        Buffer.BlockCopy(data, 0, protectedData, Prefix.Length, data.Length);
        return protectedData;
    }

    public byte[] Unprotect(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length < Prefix.Length || !data.Take(Prefix.Length).SequenceEqual(Prefix))
        {
            throw new CryptographicException("The protected payload is invalid.");
        }

        return data.Skip(Prefix.Length).ToArray();
    }
}
