using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Ashlar.Passkeys;

/// <summary>
/// Implements passkey ceremonies using fido2-net-lib.
/// </summary>
public sealed class Fido2PasskeyCeremonyValidator : IPasskeyCeremonyValidator
{
    // WebAuthn authenticator data stores flags at byte 32, after the 32-byte RP ID hash.
    private const int AuthenticatorDataFlagsOffset = 32;
    private const byte UserVerifiedFlag = 0x04;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly Func<string, CancellationToken, Task<bool>> _isCredentialRegisteredAsync;
    private readonly Func<Fido2NetLib.Fido2, MakeNewCredentialParams, CancellationToken, Task<RegisteredPublicKeyCredential>> _makeCredentialAsync;
    private readonly Func<Fido2NetLib.Fido2, MakeAssertionParams, CancellationToken, Task<VerifyAssertionResult>> _makeAssertionAsync;

    /// <summary>Initializes the validator with the passkey-specific core lookup.</summary>
    /// <param name="credentials">The passkey-specific credential lookup.</param>
    public Fido2PasskeyCeremonyValidator(Ashlar.Identity.Passkeys.IPasskeyCredentialLookup credentials) : this(
        credentials,
        static (fido, parameters, ct) => fido.MakeNewCredentialAsync(parameters, ct),
        static (fido, parameters, ct) => fido.MakeAssertionAsync(parameters, ct))
    {
    }

    internal Fido2PasskeyCeremonyValidator(
        Ashlar.Identity.Passkeys.IPasskeyCredentialLookup credentials,
        Func<Fido2NetLib.Fido2, MakeNewCredentialParams, CancellationToken, Task<RegisteredPublicKeyCredential>> makeCredentialAsync,
        Func<Fido2NetLib.Fido2, MakeAssertionParams, CancellationToken, Task<VerifyAssertionResult>> makeAssertionAsync)
    {
        _isCredentialRegisteredAsync = (credentials ?? throw new ArgumentNullException(nameof(credentials))).IsCredentialRegisteredAsync;
        _makeCredentialAsync = makeCredentialAsync ?? throw new ArgumentNullException(nameof(makeCredentialAsync));
        _makeAssertionAsync = makeAssertionAsync ?? throw new ArgumentNullException(nameof(makeAssertionAsync));
    }

    /// <summary>Creates registration options for a browser WebAuthn ceremony.</summary>
    /// <param name="options">The passkey options.</param>
    /// <param name="user">The user registering a passkey.</param>
    /// <param name="displayName">The passkey display name.</param>
    /// <param name="challenge">The Ashlar-managed challenge.</param>
    /// <param name="existingCredentials">Existing passkey credentials for exclusion.</param>
    /// <returns>The serialized registration options.</returns>
    public string CreateRegistrationOptions(PasskeyOptions options, IUser user, string displayName, string challenge, IReadOnlyList<UserCredential> existingCredentials)
    {
        var fido = CreateFido2(options);
        var credentialOptions = fido.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                Id = user.Id.ToByteArray(),
                Name = user.DisplayEmail,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? user.DisplayEmail : displayName
            },
            ExcludeCredentials = existingCredentials.Select(ToDescriptor).ToList(),
            AuthenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = options.RequireResidentKey ? ResidentKeyRequirement.Required : ResidentKeyRequirement.Preferred,
                UserVerification = ParseUserVerification(options.RegistrationUserVerification)
            },
            AttestationPreference = ParseAttestation(options.AttestationConveyancePreference)
        });
        credentialOptions.Challenge = Base64Url.Decode(challenge);
        return credentialOptions.ToJson();
    }

    /// <summary>Verifies a registration ceremony response.</summary>
    /// <param name="options">The passkey options.</param>
    /// <param name="challenge">The stored challenge.</param>
    /// <param name="credentialResponse">The browser credential response.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The verified registration result.</returns>
    public async Task<PasskeyRegistrationVerificationResult> VerifyRegistrationAsync(PasskeyOptions options, PasskeyChallenge challenge, JsonElement credentialResponse, CancellationToken cancellationToken = default)
    {
        var fido = CreateFido2(options);
        var response = credentialResponse.Deserialize<AuthenticatorAttestationRawResponse>(JsonOptions)
            ?? throw new InvalidOperationException("Passkey registration response was empty.");
        var originalOptions = CredentialCreateOptions.FromJson(challenge.OptionsJson);
        originalOptions.Challenge = Base64Url.Decode(challenge.Challenge);
        var credential = await _makeCredentialAsync(fido, new MakeNewCredentialParams
        {
            AttestationResponse = response,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = async (args, ct) =>
                !await _isCredentialRegisteredAsync(Base64Url.Encode(args.CredentialId), ct)
        }, cancellationToken);

        return new PasskeyRegistrationVerificationResult(
            Base64Url.Encode(credential.Id),
            Base64Url.Encode(credential.PublicKey),
            credential.SignCount,
            credential.Transports?.Select(t => t.ToString()).ToArray() ?? [],
            credential.AaGuid == Guid.Empty ? null : credential.AaGuid.ToString("D"),
            Discoverable: options.RequireResidentKey,
            UserVerified: HasUserVerification(response));
    }

    /// <summary>Creates authentication options for a browser WebAuthn ceremony.</summary>
    /// <param name="options">The passkey options.</param>
    /// <param name="challenge">The Ashlar-managed challenge.</param>
    /// <param name="allowedCredentials">Allowed credentials for user-scoped flows.</param>
    /// <param name="userVerification">The WebAuthn user verification requirement.</param>
    /// <returns>The serialized authentication options.</returns>
    public string CreateAuthenticationOptions(PasskeyOptions options, string challenge, IReadOnlyList<UserCredential> allowedCredentials, string userVerification)
    {
        var fido = CreateFido2(options);
        var assertionOptions = fido.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowedCredentials.Select(ToDescriptor).ToList(),
            UserVerification = ParseUserVerification(userVerification)
        });
        assertionOptions.Challenge = Base64Url.Decode(challenge);
        return assertionOptions.ToJson();
    }

    /// <summary>Verifies an authentication ceremony response.</summary>
    /// <param name="options">The passkey options.</param>
    /// <param name="challenge">The stored challenge.</param>
    /// <param name="credential">The stored credential.</param>
    /// <param name="assertionResponse">The browser assertion response.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The verified authentication result.</returns>
    public async Task<PasskeyAuthenticationVerificationResult> VerifyAuthenticationAsync(PasskeyOptions options, PasskeyChallenge challenge, UserCredential credential, JsonElement assertionResponse, CancellationToken cancellationToken = default)
    {
        var metadata = string.IsNullOrWhiteSpace(credential.Metadata)
            ? throw new InvalidOperationException("Passkey credential metadata was empty.")
            : JsonSerializer.Deserialize<PasskeyCredentialMetadata>(credential.Metadata, JsonOptions) ?? throw new InvalidOperationException("Passkey credential metadata was invalid.");
        var fido = CreateFido2(options);
        var response = assertionResponse.Deserialize<AuthenticatorAssertionRawResponse>(JsonOptions)
            ?? throw new InvalidOperationException("Passkey authentication response was empty.");
        var originalOptions = AssertionOptions.FromJson(challenge.OptionsJson);
        originalOptions.Challenge = Base64Url.Decode(challenge.Challenge);
        var result = await _makeAssertionAsync(fido, new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = originalOptions,
            StoredPublicKey = Base64Url.Decode(metadata.PublicKey),
            StoredSignatureCounter = metadata.SignCount >= 0 ? (uint)Math.Min(metadata.SignCount, uint.MaxValue) : 0,
            IsUserHandleOwnerOfCredentialIdCallback = (args, _) => Task.FromResult(
                ((challenge.UserId.HasValue && args.UserHandle is null) || (args.UserHandle is not null && args.UserHandle.SequenceEqual(credential.UserId.ToByteArray())))
                && args.CredentialId.SequenceEqual(Base64Url.Decode(credential.ProviderKey)))
        }, cancellationToken);

        return new PasskeyAuthenticationVerificationResult(Base64Url.Encode(result.CredentialId), result.SignCount, HasUserVerification(response));
    }

    private static Fido2NetLib.Fido2 CreateFido2(PasskeyOptions options)
    {
        return new Fido2NetLib.Fido2(new Fido2Configuration
        {
            ServerDomain = options.RelyingPartyId,
            ServerName = options.RelyingPartyName,
            Origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { options.Origin },
            ChallengeSize = options.ChallengeBytes,
            Timeout = (uint)options.ChallengeLifetime.TotalMilliseconds
        }, null);
    }

    private static PublicKeyCredentialDescriptor ToDescriptor(UserCredential credential)
    {
        var metadata = ReadMetadata(credential.Metadata);
        var transports = metadata.Transports.Select(ParseTransport).Where(t => t.HasValue).Select(t => t!.Value).ToArray();
        return new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PublicKey, Base64Url.Decode(credential.ProviderKey), transports);
    }

    private static PasskeyCredentialMetadata ReadMetadata(string? value)
    {
        try
        {
            return string.IsNullOrWhiteSpace(value)
                ? new PasskeyCredentialMetadata()
                : JsonSerializer.Deserialize<PasskeyCredentialMetadata>(value, JsonOptions) ?? new PasskeyCredentialMetadata();
        }
        catch (JsonException)
        {
            return new PasskeyCredentialMetadata();
        }
    }

    private static UserVerificationRequirement ParseUserVerification(string? value)
    {
        return value?.Trim().ToLowerInvariant() switch
        {
            PasskeyUserVerificationRequirement.Required => UserVerificationRequirement.Required,
            PasskeyUserVerificationRequirement.Discouraged => UserVerificationRequirement.Discouraged,
            _ => UserVerificationRequirement.Preferred
        };
    }

    private static bool HasUserVerification(AuthenticatorAssertionRawResponse response)
    {
        var authenticatorData = response.Response?.AuthenticatorData;
        if (authenticatorData is not { Length: > AuthenticatorDataFlagsOffset })
        {
            return false;
        }

        return (authenticatorData[AuthenticatorDataFlagsOffset] & UserVerifiedFlag) == UserVerifiedFlag;
    }

    private static bool HasUserVerification(AuthenticatorAttestationRawResponse response)
    {
        // Registration has already been validated by fido2-net-lib; this parse reports the UV bit from the attestation authData.
        return response.Response?.AttestationObject is { Length: > 0 }
            && AuthenticatorAttestationResponse.Parse(response).AttestationObject.AuthData.UserVerified;
    }

    private static AttestationConveyancePreference ParseAttestation(string? value)
    {
        return value?.Trim().ToLowerInvariant() switch
        {
            "direct" => AttestationConveyancePreference.Direct,
            "enterprise" => AttestationConveyancePreference.Enterprise,
            "indirect" => AttestationConveyancePreference.Indirect,
            _ => AttestationConveyancePreference.None
        };
    }

    private static AuthenticatorTransport? ParseTransport(string value)
    {
        return Enum.TryParse<AuthenticatorTransport>(value, ignoreCase: true, out var transport) ? transport : null;
    }
}
