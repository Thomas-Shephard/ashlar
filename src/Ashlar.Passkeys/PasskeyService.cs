using System.Security.Cryptography;
using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;

namespace Ashlar.Passkeys;

/// <summary>
/// Provides passkey registration, authentication, and credential management operations.
/// </summary>
public sealed class PasskeyService : IPasskeyService
{
    private const string RegistrationPurpose = "passkey-registration";
    private const string AuthenticationPurpose = "passkey-authentication";
    private const string AuthenticationChallengeStartPurpose = "passkey-authentication-start";
    private const string PrimaryProviderTypeMetadataKey = "primary_provider_type";
    private const string PrimaryProviderNameMetadataKey = "primary_provider_name";
    private const string PrimaryCredentialKeyMetadataKey = "primary_credential_key";
    private readonly IUserRepository _userRepository;
    private readonly ICredentialRepository _credentialRepository;
    private readonly IPasskeyChallengeRepository _challengeRepository;
    private readonly IPasskeyCeremonyValidator _ceremonyValidator;
    private readonly IAuthenticationOrchestrator _authenticationOrchestrator;
    private readonly IAuthenticationHandshakeService _handshakeService;
    private readonly ISecureTokenHasher _tokenHasher;
    private readonly AuthenticationRateLimitChecker _rateLimitChecker;
    private readonly PasskeyOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ISecurityEventSink? _securityEventSink;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasskeyService" /> class.
    /// </summary>
    /// <param name="userRepository">Stores and retrieves users.</param>
    /// <param name="credentialRepository">Stores and retrieves credentials.</param>
    /// <param name="challengeRepository">The passkey challenge repository.</param>
    /// <param name="ceremonyValidator">The passkey ceremony validator.</param>
    /// <param name="dependencies">The passkey service dependencies.</param>
    public PasskeyService(
        IUserRepository userRepository,
        ICredentialRepository credentialRepository,
        IPasskeyChallengeRepository challengeRepository,
        IPasskeyCeremonyValidator ceremonyValidator,
        PasskeyServiceDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(dependencies);

        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _credentialRepository = credentialRepository ?? throw new ArgumentNullException(nameof(credentialRepository));
        _challengeRepository = challengeRepository ?? throw new ArgumentNullException(nameof(challengeRepository));
        _ceremonyValidator = ceremonyValidator ?? throw new ArgumentNullException(nameof(ceremonyValidator));
        _authenticationOrchestrator = dependencies.AuthenticationOrchestrator;
        _handshakeService = dependencies.HandshakeService;
        _tokenHasher = dependencies.TokenHasher;
        _rateLimitChecker = new AuthenticationRateLimitChecker(dependencies.RateLimiter);
        _options = dependencies.Options.Value;
        _timeProvider = dependencies.TimeProvider;
        _securityEventSink = dependencies.SecurityEventSink;
    }

    public async Task<PasskeyCeremonyOptions> StartRegistrationAsync(StartPasskeyRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        var user = await GetAvailableRegistrationUserAsync(request.UserId, request.Tenant, cancellationToken);
        var existing = await _credentialRepository.ListCredentialsForUserAsync(request.UserId, cancellationToken: cancellationToken);
        var displayName = NormalizeDisplayName(request.DisplayName);
        var challengeValue = CreateChallenge();
        var optionsJson = _ceremonyValidator.CreateRegistrationOptions(_options, user, displayName, challengeValue, existing.Where(IsPasskey).ToList());
        var challenge = CreateChallengeEntity(RegistrationPurpose, challengeValue, optionsJson, request.UserId, displayName: displayName, tenantId: request.Tenant?.TenantId);
        await _challengeRepository.CreateAsync(challenge, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationStarted, SecurityEventOutcomes.Success, request.UserId, null, request.Audit, cancellationToken);
        return new PasskeyCeremonyOptions(challenge.Id, optionsJson, challenge.ExpiresAt);
    }

    public async Task<Result> CompleteRegistrationAsync(CompletePasskeyRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        var challenge = await GetChallengeAsync(request.ChallengeId, RegistrationPurpose, cancellationToken);
        if (challenge == null || challenge.UserId == null)
        {
            return Result.Failure(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        if (request.UserId.HasValue && request.UserId.Value != challenge.UserId.Value)
        {
            return Result.Failure(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        if (request.Tenant?.TenantId != challenge.TenantId)
        {
            return Result.Failure(AshlarFailureCodes.TenantMismatch);
        }

        var user = await _userRepository.GetUserByIdAsync(challenge.UserId.Value, cancellationToken);
        if (user == null)
        {
            return Result.Failure(AshlarFailureCodes.UserNotFound);
        }

        if (!UserTenantOwnership.Matches(user, challenge.TenantId))
        {
            return Result.Failure(AshlarFailureCodes.TenantMismatch);
        }

        if (!user.CanSignIn())
        {
            return Result.Failure(AshlarFailureCodes.UserNotFoundOrUnavailable);
        }

        if (!await _challengeRepository.ConsumeAsync(challenge.Id, challenge.Version, _timeProvider.GetUtcNow(), cancellationToken))
        {
            return Result.Failure(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        PasskeyRegistrationVerificationResult verified;
        try
        {
            verified = await _ceremonyValidator.VerifyRegistrationAsync(_options, challenge, request.CredentialResponse, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationCompleted, SecurityEventOutcomes.Failure, challenge.UserId, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return Result.Failure(AshlarFailureCodes.PasskeyValidationFailed);
        }

        var metadata = new PasskeyCredentialMetadata
        {
            DisplayName = ResolveDisplayName(request.DisplayName, challenge.DisplayName),
            PublicKey = verified.PublicKey,
            SignCount = verified.SignCount,
            Transports = verified.Transports,
            Aaguid = verified.Aaguid,
            AuthenticatorAttachment = verified.AuthenticatorAttachment,
            Discoverable = verified.Discoverable
        };

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = challenge.UserId.Value,
            ProviderType = _options.ProviderKey.Type,
            ProviderName = _options.ProviderKey.Name,
            ProviderKey = verified.CredentialId,
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active,
            Purpose = "primary",
            Metadata = JsonSerializer.Serialize(metadata, PasskeyJson.Options)
        };

        try
        {
            await _credentialRepository.CreateOrReplaceCredentialAsync(credential, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationCompleted, SecurityEventOutcomes.Failure, challenge.UserId, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return Result.Failure(AshlarFailureCodes.PasskeyValidationFailed);
        }

        await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationCompleted, SecurityEventOutcomes.Success, challenge.UserId, null, request.Audit, cancellationToken);
        return Result.Success();
    }

    public async Task<Result<PasskeyCeremonyOptions>> StartAuthenticationAsync(StartPasskeyAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        var context = ToAuthenticationContext(request.Audit);
        var sourceBucket = AuthenticationRateLimitDimensions.Source(context);
        var rateLimit = await _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck(
            AuthenticationChallengeStartPurpose,
            AuthenticationRateLimitDimensions.DimensionName(sourceBucket),
            sourceBucket,
            _options.AuthenticationChallengeStartRateLimit)
        {
            Context = context,
            UserId = request.UserId
        }, cancellationToken);

        if (!rateLimit.IsAllowed)
        {
            await RecordAsync(AshlarSecurityEventTypes.AuthenticationRateLimited, SecurityEventOutcomes.Failure, request.UserId, SecurityEventFailureReasons.RateLimited, request.Audit, cancellationToken);
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.RateLimited);
        }

        Guid? userId = request.UserId;
        var credentials = userId.HasValue
            ? (await _credentialRepository.ListCredentialsForUserAsync(userId.Value, cancellationToken: cancellationToken)).Where(IsPasskey).ToList()
            : [];
        var challengeValue = CreateChallenge();
        var optionsJson = _ceremonyValidator.CreateAuthenticationOptions(_options, challengeValue, credentials, _options.AuthenticationUserVerification);
        var challenge = CreateChallengeEntity(AuthenticationPurpose, challengeValue, optionsJson, userId);
        await _challengeRepository.CreateAsync(challenge, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationStarted, SecurityEventOutcomes.Success, userId, null, request.Audit, cancellationToken);
        return Result.Success(new PasskeyCeremonyOptions(challenge.Id, optionsJson, challenge.ExpiresAt));
    }

    public async Task<PasskeyAuthenticationResult> CompleteAuthenticationAsync(CompletePasskeyAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        var challenge = await GetChallengeAsync(request.ChallengeId, AuthenticationPurpose, cancellationToken);
        if (challenge == null)
        {
            return FailedAuthentication(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var ceremony = await CompleteAssertionCeremonyAsync(challenge, request.AssertionResponse, request.Audit, cancellationToken);
        if (ceremony is FailedPasskeyAssertion failed)
        {
            return failed.Failure;
        }

        var succeededCeremony = (SucceededPasskeyAssertion)ceremony;

        if (IsUserVerificationRequired(_options.AuthenticationUserVerification) && !succeededCeremony.Verified.UserVerified)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed, succeededCeremony.User);
        }

        try
        {
            var response = await _authenticationOrchestrator.AuthenticateAsync(ToAuthenticationContext(request.Audit) with { TenantId = request.TenantId, UserId = succeededCeremony.User.Id }, succeededCeremony.ToAssertion(_options.ProviderKey), cancellationToken: cancellationToken);
            var succeeded = response.Status == MfaAuthenticationStatus.Succeeded;
            var mfaRequired = response.Status == MfaAuthenticationStatus.MfaRequired;
            var failureCode = succeeded || mfaRequired ? (AshlarFailureCode?)null : AshlarFailureCodes.PasskeyValidationFailed;
            if (failureCode is not null)
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
                return new PasskeyAuthenticationResult(
                    Succeeded: false,
                    User: response.User,
                    Credential: null,
                    FailureCode: failureCode,
                    AuthenticationStatus: response.Status,
                    ErrorMessage: response.ErrorMessage);
            }

            var updatedCredential = await PersistSuccessfulAssertionAsync(succeededCeremony, response.CredentialUpdatePersisted, cancellationToken);
            if (updatedCredential == null)
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
                return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed, succeededCeremony.User);
            }

            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Success, succeededCeremony.User.Id, null, request.Audit, cancellationToken);
            var summary = ToSummary(updatedCredential);
            return new PasskeyAuthenticationResult(
                Succeeded: succeeded,
                User: response.User,
                Credential: summary,
                FailureCode: null,
                AuthenticationStatus: response.Status,
                HandshakeToken: response.HandshakeToken,
                RequiredFactors: response.RequiredFactors,
                ErrorMessage: response.ErrorMessage);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed);
        }
    }

    public async Task<Result<PasskeyCeremonyOptions>> StartFactorAsync(StartPasskeyFactorRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.FactorType))
        {
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var factorType = NormalizeFactorType(request.FactorType);
        if (factorType == null)
        {
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var handshakeResult = await _handshakeService.BeginFactorChallengeAsync(
            new VerifyAuthenticationHandshakeRequest(request.HandshakeToken, factorType, Context: ToAuthenticationContext(request.Audit)),
            cancellationToken);
        if (!handshakeResult.Succeeded || handshakeResult.Value == null)
        {
            var failureCode = handshakeResult.FailureCode == AshlarFailureCodes.RateLimitExceeded
                ? AshlarFailureCodes.RateLimitExceeded
                : AshlarFailureCodes.PasskeyChallengeInvalid;
            return Result.Failure<PasskeyCeremonyOptions>(failureCode);
        }

        var handshake = handshakeResult.Value;
        if (!SecureTokenHashing.TryHashToken(_tokenHasher, request.HandshakeToken, out var handshakeTokenHash))
        {
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var credentials = (await _credentialRepository.ListCredentialsForUserAsync(handshake.UserId, cancellationToken: cancellationToken))
            .Where(IsPasskey)
            .Where(credential => !IsPrimaryCredential(handshake, credential))
            .ToList();
        if (credentials.Count == 0)
        {
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        var challengeValue = CreateChallenge();
        var optionsJson = _ceremonyValidator.CreateAuthenticationOptions(_options, challengeValue, credentials, PasskeyUserVerificationRequirement.Required);
        var challenge = CreateChallengeEntity(
            AuthenticationPurpose,
            challengeValue,
            optionsJson,
            handshake.UserId,
            handshakeTokenHash,
            factorType);
        await _challengeRepository.CreateAsync(challenge, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationStarted, SecurityEventOutcomes.Success, handshake.UserId, null, request.Audit, cancellationToken);
        return Result.Success(new PasskeyCeremonyOptions(challenge.Id, optionsJson, challenge.ExpiresAt));
    }

    public async Task<PasskeyAuthenticationResult> CompleteFactorAsync(CompletePasskeyFactorRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.FactorType))
        {
            return FailedAuthentication(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var factorType = NormalizeFactorType(request.FactorType);
        if (factorType == null)
        {
            return FailedAuthentication(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        if (!SecureTokenHashing.TryHashToken(_tokenHasher, request.HandshakeToken, out var handshakeTokenHash))
        {
            return FailedAuthentication(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var challenge = await GetChallengeAsync(request.ChallengeId, AuthenticationPurpose, cancellationToken);
        if (challenge == null
            || !challenge.UserId.HasValue
            || !string.Equals(challenge.HandshakeTokenHash, handshakeTokenHash, StringComparison.Ordinal)
            || !string.Equals(challenge.FactorType, factorType, StringComparison.Ordinal))
        {
            return FailedAuthentication(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var ceremony = await CompleteAssertionCeremonyAsync(challenge, request.AssertionResponse, request.Audit, cancellationToken);
        if (ceremony is FailedPasskeyAssertion failed)
        {
            return failed.Failure;
        }

        var succeededCeremony = (SucceededPasskeyAssertion)ceremony;

        if (!succeededCeremony.Verified.UserVerified)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed, succeededCeremony.User);
        }

        try
        {
            var response = await _authenticationOrchestrator.VerifyFactorAsync(
                request.HandshakeToken,
                factorType,
                ToAuthenticationContext(request.Audit) with { TenantId = request.TenantId, UserId = succeededCeremony.User.Id },
                succeededCeremony.ToAssertion(_options.ProviderKey),
                cancellationToken);

            var succeeded = response.Status == MfaAuthenticationStatus.Succeeded;
            var incomplete = response.Status == MfaAuthenticationStatus.HandshakeIncomplete;
            if (!succeeded && !incomplete)
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
                return new PasskeyAuthenticationResult(
                    Succeeded: false,
                    User: response.User,
                    Credential: null,
                    FailureCode: AshlarFailureCodes.PasskeyValidationFailed,
                    AuthenticationStatus: response.Status,
                    HandshakeToken: response.HandshakeToken,
                    RequiredFactors: response.RequiredFactors,
                    ErrorMessage: response.ErrorMessage);
            }

            var updatedCredential = await PersistSuccessfulAssertionAsync(succeededCeremony, response.CredentialUpdatePersisted, cancellationToken);
            if (updatedCredential == null)
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
                return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed, succeededCeremony.User);
            }

            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Success, succeededCeremony.User.Id, null, request.Audit, cancellationToken);
            return new PasskeyAuthenticationResult(
                Succeeded: succeeded,
                User: response.User,
                Credential: ToSummary(updatedCredential),
                FailureCode: null,
                AuthenticationStatus: response.Status,
                HandshakeToken: response.HandshakeToken,
                RequiredFactors: response.RequiredFactors,
                ErrorMessage: response.ErrorMessage);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed);
        }
    }

    public async Task<IReadOnlyList<PasskeyCredentialSummary>> ListAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var credentials = await _credentialRepository.ListCredentialsForUserAsync(userId, cancellationToken: cancellationToken);
        return credentials.Where(IsPasskey).Select(ToSummary).ToList().AsReadOnly();
    }

    public async Task<Result> RenameAsync(RenamePasskeyRequest request, CancellationToken cancellationToken = default)
    {
        var credential = (await _credentialRepository.ListCredentialsForUserAsync(request.UserId, cancellationToken: cancellationToken)).FirstOrDefault(c => c.Id == request.CredentialId && IsPasskey(c));
        if (credential == null)
        {
            return Result.Failure(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        if (!PasskeyCredentialMetadataOperations.TryRead(credential.Metadata, out var metadata))
        {
            return Result.Failure(AshlarFailureCodes.PasskeyValidationFailed);
        }

        metadata.DisplayName = NormalizeDisplayName(request.DisplayName);
        credential.Metadata = JsonSerializer.Serialize(metadata, PasskeyJson.Options);
        var updated = await _credentialRepository.UpdateCredentialAsync(credential, credential.Version, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyRenamed, updated ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure, request.UserId, updated ? null : AshlarFailureCodes.ConcurrencyConflict.Value, request.Audit, cancellationToken);
        return updated ? Result.Success() : Result.Failure(AshlarFailureCodes.ConcurrencyConflict);
    }

    public async Task<Result> RevokeAsync(RevokePasskeyRequest request, CancellationToken cancellationToken = default)
    {
        var credential = (await _credentialRepository.ListCredentialsForUserAsync(request.UserId, cancellationToken: cancellationToken)).FirstOrDefault(c => c.Id == request.CredentialId && IsPasskey(c));
        if (credential == null)
        {
            return Result.Failure(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        credential.Status = CredentialStatus.Revoked;
        credential.RevokedAt = _timeProvider.GetUtcNow();
        var updated = await _credentialRepository.UpdateCredentialAsync(credential, credential.Version, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyRevoked, updated ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure, request.UserId, updated ? null : AshlarFailureCodes.ConcurrencyConflict.Value, request.Audit, cancellationToken);
        return updated ? Result.Success() : Result.Failure(AshlarFailureCodes.ConcurrencyConflict);
    }

    private async Task<PasskeyChallenge?> GetChallengeAsync(Guid id, string purpose, CancellationToken cancellationToken)
    {
        var challenge = await _challengeRepository.GetAsync(id, cancellationToken);
        var now = _timeProvider.GetUtcNow();
        return challenge is { ConsumedAt: null }
            && challenge.Purpose == purpose
            && challenge.ExpiresAt > now
            && string.Equals(challenge.RelyingPartyId, _options.RelyingPartyId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(challenge.Origin, _options.Origin, StringComparison.OrdinalIgnoreCase)
            ? challenge
            : null;
    }

    private async Task<IPasskeyAssertionCompletion> CompleteAssertionCeremonyAsync(PasskeyChallenge challenge, JsonElement assertionResponse, AuditContext? audit, CancellationToken cancellationToken)
    {
        if (!await _challengeRepository.ConsumeAsync(challenge.Id, challenge.Version, _timeProvider.GetUtcNow(), cancellationToken))
        {
            return FailedAssertion(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var credentialId = assertionResponse.TryGetProperty("id", out var id) ? id.GetString() : null;
        if (string.IsNullOrWhiteSpace(credentialId))
        {
            return FailedAssertion(AshlarFailureCodes.PasskeyValidationFailed);
        }

        var user = challenge.UserId.HasValue
            ? await _userRepository.GetUserByIdAsync(challenge.UserId.Value, cancellationToken)
            : await _userRepository.GetUserByProviderKeyAsync(_options.ProviderKey.Type, _options.ProviderKey.Name, credentialId, cancellationToken);
        if (user == null)
        {
            return FailedAssertion(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        var credential = await _credentialRepository.GetCredentialForUserAsync(user.Id, _options.ProviderKey.Type, _options.ProviderKey.Name, credentialId, cancellationToken);
        if (credential == null)
        {
            return FailedAssertion(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        try
        {
            var verified = await _ceremonyValidator.VerifyAuthenticationAsync(_options, challenge, credential, assertionResponse, cancellationToken);
            return new SucceededPasskeyAssertion(user, credential, verified);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, user.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, audit, cancellationToken);
            return FailedAssertion(AshlarFailureCodes.PasskeyValidationFailed);
        }
    }

    private async Task<UserCredential?> PersistSuccessfulAssertionAsync(SucceededPasskeyAssertion assertion, bool alreadyPersisted, CancellationToken cancellationToken)
    {
        var credential = assertion.Credential.Clone();
        if (!TryApplyVerifiedAssertionMetadata(credential, assertion.Verified.SignCount))
        {
            return null;
        }

        if (alreadyPersisted)
        {
            var persisted = await _credentialRepository.GetCredentialForUserAsync(credential.UserId, credential.ProviderType, credential.ProviderName, credential.ProviderKey, cancellationToken);
            return IsPersistedAssertionCurrent(persisted, assertion.Verified.SignCount, assertion.Credential.Version) ? persisted : null;
        }

        credential.LastUsedAt = _timeProvider.GetUtcNow();
        return await _credentialRepository.UpdateCredentialAsync(credential, assertion.Credential.Version, cancellationToken)
            ? credential
            : null;
    }

    private static bool IsPersistedAssertionCurrent(UserCredential? credential, long signCount, string originalVersion)
    {
        return credential != null
            && credential.LastUsedAt.HasValue
            && !string.Equals(credential.Version, originalVersion, StringComparison.Ordinal)
            && PasskeyCredentialMetadataOperations.TryRead(credential.Metadata, out var metadata)
            && metadata.SignCount == signCount;
    }

    private static bool TryApplyVerifiedAssertionMetadata(UserCredential credential, long signCount)
    {
        if (!PasskeyCredentialMetadataOperations.TryUpdateAssertionMetadata(credential.Metadata, signCount, out var metadata))
        {
            return false;
        }

        credential.Metadata = metadata;
        return true;
    }

    private async Task<IUser> GetAvailableRegistrationUserAsync(Guid userId, TenantContext? tenant, CancellationToken cancellationToken)
    {
        var user = await _userRepository.GetUserByIdAsync(userId, cancellationToken)
            ?? throw new InvalidOperationException("User was not found.");

        if (!UserTenantOwnership.Matches(user, tenant?.TenantId))
        {
            throw new InvalidOperationException("User was not found.");
        }

        if (!user.CanSignIn())
        {
            throw new InvalidOperationException("User account is unavailable.");
        }

        return user;
    }

    private PasskeyChallenge CreateChallengeEntity(string purpose, string challenge, string optionsJson, Guid? userId, string? handshakeTokenHash = null, string? factorType = null, string? displayName = null, Guid? tenantId = null)
    {
        var now = _timeProvider.GetUtcNow();
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = Guid.NewGuid().ToString("N"),
            Purpose = purpose,
            UserId = userId,
            TenantId = tenantId,
            HandshakeTokenHash = handshakeTokenHash,
            FactorType = factorType,
            DisplayName = displayName,
            Challenge = challenge,
            OptionsJson = optionsJson,
            RelyingPartyId = _options.RelyingPartyId,
            Origin = _options.Origin,
            CreatedAt = now,
            ExpiresAt = now.Add(_options.ChallengeLifetime)
        };
    }

    private static string? NormalizeFactorType(string factorType)
    {
        return string.Equals(factorType.Trim(), "passkey", StringComparison.OrdinalIgnoreCase) ? "passkey" : null;
    }

    private static bool IsUserVerificationRequired(string? userVerification)
    {
        return string.Equals(userVerification?.Trim(), PasskeyUserVerificationRequirement.Required, StringComparison.OrdinalIgnoreCase);
    }

    private static AuthenticationContext ToAuthenticationContext(AuditContext? audit)
    {
        return audit == null
            ? new AuthenticationContext()
            : new AuthenticationContext(IpAddress: audit.IpAddress, UserAgent: audit.UserAgent, CorrelationId: audit.CorrelationId);
    }

    private string CreateChallenge()
    {
        return Base64Url.Encode(RandomNumberGenerator.GetBytes(_options.ChallengeBytes));
    }

    private static string NormalizeDisplayName(string? displayName)
    {
        var normalized = string.IsNullOrWhiteSpace(displayName) ? "Passkey" : displayName.Trim();
        return normalized.Length <= 100 ? normalized : normalized[..100];
    }

    private static string ResolveDisplayName(string? requestedDisplayName, string? challengeDisplayName)
    {
        return string.IsNullOrWhiteSpace(requestedDisplayName)
            ? NormalizeDisplayName(challengeDisplayName)
            : NormalizeDisplayName(requestedDisplayName);
    }

    private bool IsPasskey(UserCredential credential)
    {
        return credential.ProviderType == _options.ProviderKey.Type && string.Equals(credential.ProviderName, _options.ProviderKey.Name, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPrimaryCredential(AuthenticationHandshake handshake, UserCredential credential)
    {
        return handshake.Metadata != null
            && handshake.Metadata.TryGetValue(PrimaryProviderTypeMetadataKey, out var providerType)
            && handshake.Metadata.TryGetValue(PrimaryProviderNameMetadataKey, out var providerName)
            && handshake.Metadata.TryGetValue(PrimaryCredentialKeyMetadataKey, out var credentialKey)
            && string.Equals(providerType, credential.ProviderType.Value, StringComparison.OrdinalIgnoreCase)
            && string.Equals(providerName, credential.ProviderName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(credentialKey, credential.ProviderKey, StringComparison.Ordinal);
    }

    private static PasskeyCredentialSummary ToSummary(UserCredential credential)
    {
        var metadata = ReadMetadata(credential);
        return new PasskeyCredentialSummary(credential.Id, credential.ProviderKey, metadata.DisplayName, credential.CreatedAt, credential.LastUsedAt, metadata.SignCount, metadata.Transports);
    }

    private static PasskeyCredentialMetadata ReadMetadata(UserCredential credential)
    {
        return PasskeyCredentialMetadataOperations.ReadOrDefault(credential.Metadata);
    }

    private Task RecordAsync(string eventType, string outcome, Guid? userId, string? failureReason, AuditContext? audit, CancellationToken cancellationToken)
    {
        if (_securityEventSink == null)
        {
            return Task.CompletedTask;
        }

        return _securityEventSink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            Outcome = outcome,
            OccurredAt = _timeProvider.GetUtcNow(),
            UserId = userId,
            ActorUserId = audit?.ActorUserId,
            IpAddress = audit?.IpAddress,
            UserAgent = audit?.UserAgent,
            CorrelationId = audit?.CorrelationId,
            Provider = _options.ProviderKey,
            FailureReason = failureReason
        }, cancellationToken);
    }

    private static PasskeyAuthenticationResult FailedAuthentication(AshlarFailureCode failureCode, IUser? user = null)
    {
        return new PasskeyAuthenticationResult(
            Succeeded: false,
            User: user,
            Credential: null,
            FailureCode: failureCode);
    }

    private static FailedPasskeyAssertion FailedAssertion(AshlarFailureCode failureCode)
    {
        return new FailedPasskeyAssertion(FailedAuthentication(failureCode));
    }

}

internal interface IPasskeyAssertionCompletion;

internal sealed record FailedPasskeyAssertion(PasskeyAuthenticationResult Failure) : IPasskeyAssertionCompletion;

internal sealed record SucceededPasskeyAssertion(
    IUser User,
    UserCredential Credential,
    PasskeyAuthenticationVerificationResult Verified) : IPasskeyAssertionCompletion
{
    public PasskeyAssertion ToAssertion(AuthenticationProviderKey providerKey)
    {
        return new PasskeyAssertion(Verified.CredentialId, Verified.SignCount, Verified.UserVerified, providerKey);
    }
}

/// <summary>
/// Provides passkey service dependencies.
/// </summary>
/// <param name="options">The passkey options.</param>
/// <param name="authenticationOrchestrator">The orchestrator for MFA-aware authentication flows.</param>
/// <param name="handshakeService">The authentication handshake service.</param>
/// <param name="tokenHasher">The secure token hasher.</param>
/// <param name="rateLimiter">The authentication rate limiter.</param>
/// <param name="timeProvider">The time provider.</param>
/// <param name="securityEventSink">The security event sink.</param>
public sealed class PasskeyServiceDependencies(
    IOptions<PasskeyOptions> options,
    IAuthenticationOrchestrator authenticationOrchestrator,
    IAuthenticationHandshakeService handshakeService,
    ISecureTokenHasher tokenHasher,
    IAuthenticationRateLimiter rateLimiter,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null)
{
    /// <summary>
    /// Gets the configured passkey options.
    /// </summary>
    public IOptions<PasskeyOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));
    /// <summary>
    /// Gets the orchestrator used to complete authentication flows.
    /// </summary>
    public IAuthenticationOrchestrator AuthenticationOrchestrator { get; } = authenticationOrchestrator ?? throw new ArgumentNullException(nameof(authenticationOrchestrator));
    /// <summary>
    /// Gets the service used to create and inspect passkey authentication handshakes.
    /// </summary>
    public IAuthenticationHandshakeService HandshakeService { get; } = handshakeService ?? throw new ArgumentNullException(nameof(handshakeService));
    /// <summary>
    /// Gets the hasher used for passkey handshake tokens.
    /// </summary>
    public ISecureTokenHasher TokenHasher { get; } = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));
    /// <summary>
    /// Gets the rate limiter used for passkey ceremony starts.
    /// </summary>
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    /// <summary>
    /// Gets the configured time provider.
    /// </summary>
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;
    /// <summary>
    /// Gets the configured security event sink.
    /// </summary>
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
}
