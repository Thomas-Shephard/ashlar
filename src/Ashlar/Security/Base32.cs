using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Security;

/// <summary>
/// Provides high-performance, allocation-optimized Base32 encoding and decoding according to RFC 4648.
/// </summary>
internal static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return string.Empty;

        int outputLength = (data.Length * 8 + 4) / 5;
        char[]? pooledArray = null;
        if (outputLength > 128)
        {
            pooledArray = System.Buffers.ArrayPool<char>.Shared.Rent(outputLength);
        }

        Span<char> chars = pooledArray is null
            ? stackalloc char[outputLength]
            : pooledArray.AsSpan(0, outputLength);

        try
        {
            int buffer = data[0];
            int next = 1;
            int bitsLeft = 8;
            int charIndex = 0;

            while (bitsLeft > 0 || next < data.Length)
            {
                if (bitsLeft < 5)
                {
                    if (next < data.Length)
                    {
                        buffer <<= 8;
                        buffer |= data[next++] & 0xFF;
                        bitsLeft += 8;
                    }
                    else
                    {
                        int pad = 5 - bitsLeft;
                        buffer <<= pad;
                        bitsLeft += pad;
                    }
                }

                int index = 0x1F & (buffer >> (bitsLeft - 5));
                bitsLeft -= 5;
                chars[charIndex++] = Alphabet[index];
            }

            return new string(chars[..charIndex]);
        }
        finally
        {
            if (pooledArray != null)
            {
                System.Buffers.ArrayPool<char>.Shared.Return(pooledArray, clearArray: true);
            }
        }
    }

    public static bool TryDecode(string? base32, [NotNullWhen(true)] out byte[]? result)
    {
        result = null;
        if (string.IsNullOrEmpty(base32))
        {
            result = [];
            return true;
        }

        ReadOnlySpan<char> input = base32.AsSpan().TrimEnd('=');
        if (input.IsEmpty)
        {
            result = [];
            return true;
        }

        // Validate length: Base32 groups of 8 chars represent 5 bytes.
        // Valid lengths are (n*8) + {0, 2, 4, 5, 7}
        if (!HasValidEncodedLength(input.Length)) return false;

        int outputLength = input.Length * 5 / 8;
        byte[] decoded = new byte[outputLength];

        int buffer = 0;
        int bitsLeft = 0;
        int next = 0;

        foreach (char c in input)
        {
            int val = DecodeChar(c);
            if (val < 0) return false;

            buffer <<= 5;
            buffer |= val;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                decoded[next++] = (byte)((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }

        // RFC 4648: Check that trailing bits are zero.
        if (bitsLeft > 0)
        {
            int mask = (1 << bitsLeft) - 1;
            if ((buffer & mask) != 0) return false;
        }

        result = decoded;
        return true;
    }

    private static bool HasValidEncodedLength(int length)
    {
        int remainder = length % 8;
        return remainder is not (1 or 3 or 6);
    }

    private static int DecodeChar(char c)
    {
        return c switch
        {
            >= 'A' and <= 'Z' => c - 'A',
            >= 'a' and <= 'z' => c - 'a',
            >= '2' and <= '7' => c - '2' + 26,
            _ => -1
        };
    }
}
