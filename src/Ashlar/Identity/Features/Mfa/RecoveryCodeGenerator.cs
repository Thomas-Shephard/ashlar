using System.Security.Cryptography;
using System.Text;

namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Utility for generating human-readable recovery codes.
/// </summary>
internal static class RecoveryCodeGenerator
{
    // Avoid ambiguous characters: 0, O, 1, I, L, 5, S, 8, B
    private const string AllowedCharacters = "ACDEFGHJKMNPQRTUVWXYZ234679";

    /// <summary>
    /// Generates a human-readable recovery code.
    /// </summary>
    /// <param name="length">The length value.</param>
    /// <param name="groupSize">The group size value.</param>
    /// <returns>The operation result.</returns>
    public static string GenerateCode(int length, int groupSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(groupSize);

        var sb = new StringBuilder();

        for (int i = 0; i < length; i++)
        {
            if (i > 0 && i % groupSize == 0)
            {
                sb.Append('-');
            }

            sb.Append(AllowedCharacters[RandomNumberGenerator.GetInt32(AllowedCharacters.Length)]);
        }

        return sb.ToString();
    }
}
