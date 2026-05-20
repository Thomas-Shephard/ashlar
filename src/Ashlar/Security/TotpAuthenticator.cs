using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace Ashlar.Security;

/// <summary>
/// Provides allocation-optimized TOTP (RFC 6238) and HOTP (RFC 4226) authentication logic.
/// </summary>
internal static class TotpAuthenticator
{
    private static readonly int[] PowersOf10 = [0, 0, 0, 0, 0, 0, 1000000, 10000000, 100000000];
    private static readonly string[] Formats = ["", "", "", "", "", "", "D6", "D7", "D8"];

    /// <summary>
    /// Performs the generate code operation and returns the result.
    /// </summary>
    /// <param name="key">The key value.</param>
    /// <param name="counter">The counter value.</param>
    /// <param name="digits">The digits value.</param>
    /// <returns>The operation result.</returns>
    public static string GenerateCode(ReadOnlySpan<byte> key, long counter, int digits = 6)
    {
        if (digits is < 6 or > 8) throw new ArgumentOutOfRangeException(nameof(digits), "TOTP digits must be between 6 and 8.");

        Span<byte> counterBytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);

#pragma warning disable CA5350 // HMACSHA1 is the standard for TOTP
        Span<byte> hash = stackalloc byte[HMACSHA1.HashSizeInBytes];
        HMACSHA1.HashData(key, counterBytes, hash);
#pragma warning restore CA5350

        int offset = hash[^1] & 0x0F;

        int binaryCode = ((hash[offset] & 0x7F) << 24)
                         | ((hash[offset + 1] & 0xFF) << 16)
                         | ((hash[offset + 2] & 0xFF) << 8)
                         | (hash[offset + 3] & 0xFF);

        int otp = binaryCode % PowersOf10[digits];
        return otp.ToString(Formats[digits], CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Performs the verify code operation and returns the result.
    /// </summary>
    /// <param name="key">The key value.</param>
    /// <param name="code">The code value.</param>
    /// <param name="counter">The counter value.</param>
    /// <param name="digits">The digits value.</param>
    /// <returns>The operation result.</returns>
    public static bool VerifyCode(ReadOnlySpan<byte> key, string code, long counter, int digits = 6)
    {
        // Generate expected code first to maintain consistent timing regardless of input length.
        string expectedCode = GenerateCode(key, counter, digits);

        if (string.IsNullOrEmpty(code) || code.Length != digits) return false;

        return CryptographicOperations.FixedTimeEquals(
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(expectedCode.AsSpan()),
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(code.AsSpan()));
    }

    /// <summary>
    /// Initializes a new instance of the static class.
    /// </summary>
    /// <param name="Verified">The verified value.</param>
    /// <param name="stepSeconds">The step seconds value.</param>
    public static (bool Verified, long VerifiedStep) VerifyTotp(ReadOnlySpan<byte> key, string code, DateTimeOffset time, int stepSeconds = 30, int digits = 6, int skewSteps = 1)
    {
        long unixTime = time.ToUnixTimeSeconds();
        long currentStep = unixTime / stepSeconds;

        bool verified = false;
        long verifiedStep = 0;
        for (int i = -skewSteps; i <= skewSteps; i++)
        {
            long step = currentStep + i;
            // We use a logical OR to avoid early return and maintain more consistent timing,
            // though HMAC operations dominate the cost anyway.
            bool match = VerifyCode(key, code, step, digits);
            verified |= match;
            if (match)
            {
                verifiedStep = step;
            }
        }

        return (verified, verifiedStep);
    }

    /// <summary>
    /// Performs the create otp auth uri operation and returns the result.
    /// </summary>
    /// <param name="type">The type value.</param>
    /// <param name="secret">The secret value.</param>
    /// <param name="accountName">The account name value.</param>
    /// <param name="issuer">The issuer value.</param>
    /// <param name="digits">The digits value.</param>
    /// <param name="period">The period value.</param>
    /// <returns>The operation result.</returns>
    public static string CreateOtpAuthUri(string type, string secret, string accountName, string issuer, int digits = 6, int period = 30)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(accountName);

        // otpauth://totp/Issuer:Account?secret=SECRET&issuer=Issuer&digits=6&period=30
        var label = $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(accountName)}";
        return $"otpauth://{type.ToLowerInvariant()}/{label}?secret={Uri.EscapeDataString(secret)}&issuer={Uri.EscapeDataString(issuer)}&digits={digits.ToString(CultureInfo.InvariantCulture)}&period={period.ToString(CultureInfo.InvariantCulture)}";
    }
}
