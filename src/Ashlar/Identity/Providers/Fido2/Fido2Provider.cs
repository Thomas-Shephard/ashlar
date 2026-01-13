using System.Security.Cryptography;
using System.Text.Json;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Fido2;

public sealed class Fido2Provider(IChallengeProvider challengeProvider, Fido2Options options) : IAuthenticationProvider
{
    private readonly IChallengeProvider _challengeProvider = challengeProvider ?? throw new ArgumentNullException(nameof(challengeProvider));
    private readonly Fido2Options _options = options ?? throw new ArgumentNullException(nameof(options));
    private static readonly byte[] DummyPublicKey;
    private static readonly byte[] DummySignature = new byte[64];

    static Fido2Provider()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        DummyPublicKey = ecdsa.ExportSubjectPublicKeyInfo();
        RandomNumberGenerator.Fill(DummySignature);
    }

    public ProviderType SupportedType => ProviderType.Fido2;
    public bool IsPrimary => true;
    public bool IsSecondary => true;
    public bool BypassesMfa(IAuthenticationAssertion assertion) => assertion is Fido2Assertion { UserVerified: true };

    public string? GetProviderKey(IAuthenticationAssertion assertion, IUser user) =>
        assertion is Fido2Assertion fido ? Convert.ToBase64String(fido.CredentialId) : null;

    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;

    public async Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not Fido2Assertion fidoAssertion)
        {
            return new AuthenticationResult(PasswordVerificationResult.Failed);
        }

        // Security: Validate input lengths to prevent DoS from massive payloads.
        if (fidoAssertion.ClientDataJson.Length > 4096 || 
            fidoAssertion.AuthenticatorData.Length > 1024 ||
            fidoAssertion.Signature.Length > 512)
        {
            return new AuthenticationResult(PasswordVerificationResult.Failed);
        }

        bool challengeValid = await _challengeProvider.ValidateChallengeAsync(fidoAssertion.Challenge, credential?.UserId, cancellationToken);

        // WebAuthn signature verification data: AuthenticatorData || SHA256(ClientDataJson)
        // Parse ClientDataJson to verify challenge and origin
        try
        {
            var clientDataString = System.Text.Encoding.UTF8.GetString(fidoAssertion.ClientDataJson);
            using var jsonDoc = JsonDocument.Parse(clientDataString);
            var root = jsonDoc.RootElement;

            // 1. Verify Challenge Match
            if (!root.TryGetProperty("challenge", out var challengeProp) ||
                challengeProp.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("origin", out var originProp) ||
                originProp.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("type", out var typeProp) ||
                typeProp.ValueKind != JsonValueKind.String)
            {
                 return new AuthenticationResult(PasswordVerificationResult.Failed);
            }

            var clientChallenge = challengeProp.GetString();
            var origin = originProp.GetString();
            var type = typeProp.GetString();

            if (!string.Equals(origin, _options.ExpectedOrigin, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(type, "webauthn.get", StringComparison.Ordinal))
            {
                return new AuthenticationResult(PasswordVerificationResult.Failed);
            }

            var expectedChallenge = Convert.ToBase64String(fidoAssertion.Challenge).Replace("+", "-").Replace("/", "_").TrimEnd('=');

            if (clientChallenge != expectedChallenge)
            {
                return new AuthenticationResult(PasswordVerificationResult.Failed);
            }
        }
        catch
        {
             return new AuthenticationResult(PasswordVerificationResult.Failed);
        }

        byte[] clientDataHash = SHA256.HashData(fidoAssertion.ClientDataJson);
        byte[] dataToVerify = new byte[fidoAssertion.AuthenticatorData.Length + clientDataHash.Length];
        fidoAssertion.AuthenticatorData.CopyTo(dataToVerify, 0);
        clientDataHash.CopyTo(dataToVerify, fidoAssertion.AuthenticatorData.Length);

        var publicKeyBytes = credential?.CredentialValue != null ? Convert.FromBase64String(credential.CredentialValue) : DummyPublicKey;

        bool signatureValid = VerifySignature(publicKeyBytes, fidoAssertion.Signature, dataToVerify);

        if (credential == null || !challengeValid || !signatureValid)
        {
            return new AuthenticationResult(PasswordVerificationResult.Failed);
        }

        // Production Security: Verify Signature Counter to detect cloned authenticators.
        // The counter is provided in the AuthenticatorData (bytes 33-36).
        uint signCount;
        try
        {
            signCount = ExtractCounter(fidoAssertion.AuthenticatorData);
        }
        catch (FormatException)
        {
            return new AuthenticationResult(PasswordVerificationResult.Failed);
        }

        var metadata = new Fido2Metadata();
        if (!string.IsNullOrWhiteSpace(credential.Metadata))
        {
            try
            {
                metadata = JsonSerializer.Deserialize<Fido2Metadata>(credential.Metadata) ?? new Fido2Metadata();
            }
            catch (JsonException)
            {
                // Metadata is corrupted, treat as empty
            }
        }

        if (signCount > 0 && signCount <= metadata.LastSignatureCount)
        {
            // Cloned authenticator detected!
            return new AuthenticationResult(PasswordVerificationResult.Failed);
        }

        // Prevent counter reset: if we previously saw a valid counter, strictly forbid 0.
        if (signCount == 0 && metadata.LastSignatureCount > 0)
        {
             return new AuthenticationResult(PasswordVerificationResult.Failed);
        }

        metadata.LastSignatureCount = signCount;

        return new AuthenticationResult(
            PasswordVerificationResult.Success,
            ShouldUpdateCredential: true,
            NewCredentialValue: credential.CredentialValue,
            NewMetadata: JsonSerializer.Serialize(metadata));
    }

    private static bool VerifySignature(byte[] publicKeyBytes, byte[] signature, byte[] data)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static uint ExtractCounter(byte[] authData)
    {
        if (authData.Length < 37) throw new FormatException("Authenticator data is too short.");
        // Counter is big-endian
        return ((uint)authData[33] << 24) | ((uint)authData[34] << 16) | ((uint)authData[35] << 8) | (uint)authData[36];
    }

    private sealed class Fido2Metadata
    {
        public uint LastSignatureCount { get; set; }
    }
}
