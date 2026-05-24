using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Ashlar.Passkeys;

/// <summary>
/// Implements passkey ceremonies using fido2-net-lib.
/// </summary>
public sealed class Fido2PasskeyCeremonyValidator : IPasskeyCeremonyValidator
{
    private readonly IUserRepository _userRepository;
    private readonly Func<Fido2NetLib.Fido2, MakeNewCredentialParams, CancellationToken, Task<RegisteredPublicKeyCredential>> _makeCredentialAsync;
    private readonly Func<Fido2NetLib.Fido2, MakeAssertionParams, CancellationToken, Task<VerifyAssertionResult>> _makeAssertionAsync;

    /// <summary>
    /// Initializes a new instance of the <see cref="Fido2PasskeyCeremonyValidator" /> class.
    /// </summary>
    /// <param name="userRepository">The repository used to resolve users during passkey ceremonies.</param>
    public Fido2PasskeyCeremonyValidator(IUserRepository userRepository)
        : this(userRepository, static (fido, parameters, ct) => fido.MakeNewCredentialAsync(parameters, ct), static (fido, parameters, ct) => fido.MakeAssertionAsync(parameters, ct))
    {
    }

    internal Fido2PasskeyCeremonyValidator(
        IUserRepository userRepository,
        Func<Fido2NetLib.Fido2, MakeNewCredentialParams, CancellationToken, Task<RegisteredPublicKeyCredential>> makeCredentialAsync,
        Func<Fido2NetLib.Fido2, MakeAssertionParams, CancellationToken, Task<VerifyAssertionResult>> makeAssertionAsync)
    {
        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _makeCredentialAsync = makeCredentialAsync ?? throw new ArgumentNullException(nameof(makeCredentialAsync));
        _makeAssertionAsync = makeAssertionAsync ?? throw new ArgumentNullException(nameof(makeAssertionAsync));
    }

    /// <inheritdoc />
    public string CreateRegistrationOptions(PasskeyOptions options, IUser user, string displayName, string challenge, IReadOnlyList<UserCredential> existingCredentials)
    {
        var fido = CreateFido2(options);
        var credentialOptions = fido.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                Id = user.Id.ToByteArray(),
                Name = user.Email,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? user.Email : displayName
            },
            ExcludeCredentials = existingCredentials.Select(ToDescriptor).ToList(),
            AuthenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = options.RequireResidentKey ? ResidentKeyRequirement.Required : ResidentKeyRequirement.Preferred,
                UserVerification = ParseUserVerification(options.UserVerification)
            },
            AttestationPreference = ParseAttestation(options.Attestation)
        });
        credentialOptions.Challenge = Base64Url.Decode(challenge);
        return credentialOptions.ToJson();
    }

    /// <inheritdoc />
    public async Task<PasskeyRegistrationVerificationResult> VerifyRegistrationAsync(PasskeyOptions options, PasskeyChallenge challenge, JsonElement credentialResponse, CancellationToken cancellationToken = default)
    {
        var fido = CreateFido2(options);
        var response = credentialResponse.Deserialize<AuthenticatorAttestationRawResponse>(PasskeyJson.Options)
            ?? throw new InvalidOperationException("Passkey registration response was empty.");
        var originalOptions = CredentialCreateOptions.FromJson(challenge.OptionsJson);
        originalOptions.Challenge = Base64Url.Decode(challenge.Challenge);
        var credential = await _makeCredentialAsync(fido, new MakeNewCredentialParams
        {
            AttestationResponse = response,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = async (args, ct) =>
                await _userRepository.GetUserByProviderKeyAsync(options.ProviderKey.Type, options.ProviderKey.Name, Base64Url.Encode(args.CredentialId), ct) == null
        }, cancellationToken);

        return new PasskeyRegistrationVerificationResult(
            Base64Url.Encode(credential.Id),
            Base64Url.Encode(credential.PublicKey),
            credential.SignCount,
            credential.Transports?.Select(t => t.ToString()).ToArray() ?? [],
            credential.AaGuid == Guid.Empty ? null : credential.AaGuid.ToString("D"),
            Discoverable: options.RequireResidentKey);
    }

    /// <inheritdoc />
    public string CreateAuthenticationOptions(PasskeyOptions options, string challenge, IReadOnlyList<UserCredential> allowedCredentials)
    {
        var fido = CreateFido2(options);
        var assertionOptions = fido.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowedCredentials.Select(ToDescriptor).ToList(),
            UserVerification = ParseUserVerification(options.UserVerification)
        });
        assertionOptions.Challenge = Base64Url.Decode(challenge);
        return assertionOptions.ToJson();
    }

    /// <inheritdoc />
    public async Task<PasskeyAuthenticationVerificationResult> VerifyAuthenticationAsync(PasskeyOptions options, PasskeyChallenge challenge, UserCredential credential, JsonElement assertionResponse, CancellationToken cancellationToken = default)
    {
        var metadata = string.IsNullOrWhiteSpace(credential.Metadata)
            ? throw new InvalidOperationException("Passkey credential metadata was empty.")
            : JsonSerializer.Deserialize<PasskeyCredentialMetadata>(credential.Metadata, PasskeyJson.Options) ?? throw new InvalidOperationException("Passkey credential metadata was invalid.");
        var fido = CreateFido2(options);
        var response = assertionResponse.Deserialize<AuthenticatorAssertionRawResponse>(PasskeyJson.Options)
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

        return new PasskeyAuthenticationVerificationResult(Base64Url.Encode(result.CredentialId), result.SignCount, ParseUserVerification(options.UserVerification) == UserVerificationRequirement.Required);
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
        var metadata = string.IsNullOrWhiteSpace(credential.Metadata)
            ? new PasskeyCredentialMetadata()
            : JsonSerializer.Deserialize<PasskeyCredentialMetadata>(credential.Metadata, PasskeyJson.Options) ?? new PasskeyCredentialMetadata();
        var transports = metadata.Transports.Select(ParseTransport).Where(t => t.HasValue).Select(t => t!.Value).ToArray();
        return new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PublicKey, Base64Url.Decode(credential.ProviderKey), transports);
    }

    private static UserVerificationRequirement ParseUserVerification(string value)
    {
        return value.Trim().ToLowerInvariant() switch
        {
            "required" => UserVerificationRequirement.Required,
            "discouraged" => UserVerificationRequirement.Discouraged,
            _ => UserVerificationRequirement.Preferred
        };
    }

    private static AttestationConveyancePreference ParseAttestation(string value)
    {
        return value.Trim().ToLowerInvariant() switch
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
