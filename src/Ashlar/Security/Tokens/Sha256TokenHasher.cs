using System.Security.Cryptography;
using System.Text;

namespace Ashlar.Security.Tokens;

/// <summary>
/// Hashes high-entropy, server-generated tokens with SHA-256 for deterministic lookup.
/// </summary>
/// <remarks>
/// This hasher is intentionally fast and is not suitable for low-entropy user-chosen passwords.
/// </remarks>
public sealed class Sha256TokenHasher : ISecureTokenHasher
{
    private const string Prefix = "sha256:";
    private const string HexDigits = "0123456789abcdef";
    private const int MaxTokenLength = 256;

    // A UTF-16 char can encode at most 3 UTF-8 bytes; astral characters use two chars and 4 UTF-8 bytes.
    private const int MaxTokenUtf8Bytes = MaxTokenLength * 3;

    public string HashToken(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        if (token.Length > MaxTokenLength)
        {
            throw new ArgumentException("Token exceeds maximum allowed length.", nameof(token));
        }

        return string.Create(Prefix.Length + SHA256.HashSizeInBytes * 2, token, static (span, value) =>
        {
            Prefix.AsSpan().CopyTo(span);

            Span<byte> buffer = stackalloc byte[MaxTokenUtf8Bytes];
            var bytesWritten = Encoding.UTF8.GetBytes(value, buffer);

            Span<byte> hashBuffer = stackalloc byte[SHA256.HashSizeInBytes];
            SHA256.HashData(buffer[..bytesWritten], hashBuffer);

            var hexSpan = span[Prefix.Length..];
            for (var index = 0; index < hashBuffer.Length; index++)
            {
                var current = hashBuffer[index];
                hexSpan[index * 2] = HexDigits[current >> 4];
                hexSpan[index * 2 + 1] = HexDigits[current & 0xF];
            }
        });
    }
}
