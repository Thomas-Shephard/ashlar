using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Totp;

public sealed class TotpProvider : IAuthenticationProvider
{
    private readonly TotpOptions _options;
    private static readonly byte[] DummyKey = new byte[32];

    static TotpProvider()
    {
        RandomNumberGenerator.Fill(DummyKey);
    }

    public TotpProvider(TotpOptions? options = null)
    {
        _options = options ?? new TotpOptions();
    }

    public ProviderType SupportedType => ProviderType.Totp;
    public bool IsSecondary => true;

    public string? GetProviderKey(IAuthenticationAssertion assertion, IUser user) => user.Id.ToString();

    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;

    public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not TotpAssertion totpAssertion)
        {
            return Task.FromResult(new AuthenticationResult(PasswordVerificationResult.Failed));
        }

        // The secret is stored as Base64 in CredentialValue after being unprotected by CredentialResolver
        byte[]? secret = null;
        if (credential?.CredentialValue != null)
        {
            try
            {
                secret = Convert.FromBase64String(credential.CredentialValue);
            }
            catch (FormatException)
            {
                // Fallback to dummy
            }
        }

        var metadata = new TotpMetadata();
        if (!string.IsNullOrWhiteSpace(credential?.Metadata))
        {
            try
            {
                metadata = JsonSerializer.Deserialize<TotpMetadata>(credential.Metadata) ?? new TotpMetadata();
            }
            catch (JsonException)
            {
                // Metadata is corrupted, treat as empty
            }
        }

        byte[] keyToUse = secret ?? DummyKey;
        long currentIteration = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / Math.Max(1, _options.Period);

        // Optimization: Default to SHA1 but allow metadata to override
        var algorithm = metadata.Algorithm == HashAlgorithmName.SHA256.Name
            ? HashAlgorithmName.SHA256
            : HashAlgorithmName.SHA1;

        long matchedIteration = -1;
        bool isValid = false;

        // Verify across window [-1, 0, 1] for clock skew
        for (long i = -1; i <= 1; i++)
        {
            long iter = currentIteration + i;

            // Replay Protection: Iteration must be strictly greater than last used
            if (iter <= metadata.LastUsedIteration) continue;

            if (CalculateTotp(keyToUse, iter, algorithm) == totpAssertion.Code)
            {
                isValid = true;
                matchedIteration = iter;
                break;
            }

            // If algorithm wasn't specified in metadata, try SHA256 as fallback during first success
            if (metadata.Algorithm == null && CalculateTotp(keyToUse, iter, HashAlgorithmName.SHA256) == totpAssertion.Code)
            {
                isValid = true;
                matchedIteration = iter;
                algorithm = HashAlgorithmName.SHA256;
                break;
            }
        }

        if (credential == null || secret == null || !isValid)
        {
            return Task.FromResult(new AuthenticationResult(PasswordVerificationResult.Failed));
        }

        metadata.LastUsedIteration = matchedIteration;
        metadata.Algorithm = algorithm.Name;

        return Task.FromResult(new AuthenticationResult(
            PasswordVerificationResult.Success,
            ShouldUpdateCredential: true,
            NewCredentialValue: credential.CredentialValue,
            NewMetadata: JsonSerializer.Serialize(metadata)));
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "TOTP standard often requires HMAC-SHA1")]
    private string CalculateTotp(byte[] secret, long iteration, HashAlgorithmName algorithm)
    {
        byte[] iterationBytes = BitConverter.GetBytes(iteration);
        if (BitConverter.IsLittleEndian) Array.Reverse(iterationBytes);

        using var hmac = algorithm == HashAlgorithmName.SHA256
            ? (HMAC)new HMACSHA256(secret)
            : new HMACSHA1(secret);

        byte[] hash = hmac.ComputeHash(iterationBytes);

        int offset = hash[hash.Length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7f) << 24)
                     | (hash[offset + 1] << 16)
                     | (hash[offset + 2] << 8)
                     | hash[offset + 3];

        int password = binary % (int)Math.Pow(10, _options.Digits);
        return password.ToString($"D{_options.Digits}", CultureInfo.InvariantCulture);
    }

    private sealed class TotpMetadata
    {
        public long LastUsedIteration { get; set; } = -1;
        public string? Algorithm { get; set; }
    }
}
