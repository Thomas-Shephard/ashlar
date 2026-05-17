using System.Security.Cryptography;
using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Models.Passkeys;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;

namespace Ashlar.Passkeys;

/// <summary>
/// Provides passkey registration, authentication, and credential management operations.
/// </summary>
/// <param name="identityRepository">The identity repository.</param>
/// <param name="challengeRepository">The passkey challenge repository.</param>
/// <param name="ceremonyValidator">The passkey ceremony validator.</param>
/// <param name="authenticationOrchestrator">The orchestrator for MFA-aware authentication flows.</param>
/// <param name="handshakeService">The authentication handshake service.</param>
/// <param name="tokenHasher">The secure token hasher.</param>
/// <param name="options">The passkey options.</param>
/// <param name="timeProvider">The time provider.</param>
/// <param name="securityEventSink">The security event sink.</param>
public sealed class PasskeyService(
    IIdentityRepository identityRepository,
    IPasskeyChallengeRepository challengeRepository,
    IPasskeyCeremonyValidator ceremonyValidator,
    IAuthenticationOrchestrator authenticationOrchestrator,
    IAuthenticationHandshakeService handshakeService,
    ISecureTokenHasher tokenHasher,
    IOptions<PasskeyOptions> options,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null) : IPasskeyService
{
    private const string RegistrationPurpose = "passkey-registration";
    private const string AuthenticationPurpose = "passkey-authentication";
    private const string PrimaryProviderTypeMetadataKey = "primary_provider_type";
    private const string PrimaryProviderNameMetadataKey = "primary_provider_name";
    private const string PrimaryCredentialKeyMetadataKey = "primary_credential_key";
    private readonly IIdentityRepository _identityRepository = identityRepository;
    private readonly IPasskeyChallengeRepository _challengeRepository = challengeRepository;
    private readonly IPasskeyCeremonyValidator _ceremonyValidator = ceremonyValidator;
    private readonly IAuthenticationOrchestrator _authenticationOrchestrator = authenticationOrchestrator;
    private readonly IAuthenticationHandshakeService _handshakeService = handshakeService;
    private readonly ISecureTokenHasher _tokenHasher = tokenHasher;
    private readonly PasskeyOptions _options = options.Value;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly ISecurityEventSink? _securityEventSink = securityEventSink;

    public async Task<PasskeyCeremonyOptions> StartRegistrationAsync(StartPasskeyRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _identityRepository.GetUserByIdAsync(request.UserId, cancellationToken)
            ?? throw new InvalidOperationException("User was not found.");
        var existing = await _identityRepository.ListCredentialsForUserAsync(request.UserId, cancellationToken: cancellationToken);
        var displayName = NormalizeDisplayName(request.DisplayName);
        var challengeValue = CreateChallenge();
        var optionsJson = _ceremonyValidator.CreateRegistrationOptions(_options, user, displayName, challengeValue, existing.Where(IsPasskey).ToList());
        var challenge = CreateChallengeEntity(RegistrationPurpose, challengeValue, optionsJson, request.UserId, displayName: displayName);
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
            await _identityRepository.CreateOrReplaceCredentialAsync(credential, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationCompleted, SecurityEventOutcomes.Failure, challenge.UserId, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return Result.Failure(AshlarFailureCodes.PasskeyValidationFailed);
        }

        await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationCompleted, SecurityEventOutcomes.Success, challenge.UserId, null, request.Audit, cancellationToken);
        return Result.Success();
    }

    public async Task<PasskeyCeremonyOptions> StartAuthenticationAsync(StartPasskeyAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        Guid? userId = request.UserId;
        var credentials = userId.HasValue
            ? (await _identityRepository.ListCredentialsForUserAsync(userId.Value, cancellationToken: cancellationToken)).Where(IsPasskey).ToList()
            : [];
        var challengeValue = CreateChallenge();
        var optionsJson = _ceremonyValidator.CreateAuthenticationOptions(_options, challengeValue, credentials);
        var challenge = CreateChallengeEntity(AuthenticationPurpose, challengeValue, optionsJson, userId);
        await _challengeRepository.CreateAsync(challenge, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationStarted, SecurityEventOutcomes.Success, userId, null, request.Audit, cancellationToken);
        return new PasskeyCeremonyOptions(challenge.Id, optionsJson, challenge.ExpiresAt);
    }

    public async Task<PasskeyAuthenticationResult> CompleteAuthenticationAsync(CompletePasskeyAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        var challenge = await GetChallengeAsync(request.ChallengeId, AuthenticationPurpose, cancellationToken);
        if (challenge == null)
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        if (!await _challengeRepository.ConsumeAsync(challenge.Id, challenge.Version, _timeProvider.GetUtcNow(), cancellationToken))
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var credentialId = request.AssertionResponse.TryGetProperty("id", out var id) ? id.GetString() : null;
        if (string.IsNullOrWhiteSpace(credentialId))
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyValidationFailed);
        }

        var user = challenge.UserId.HasValue
            ? await _identityRepository.GetUserByIdAsync(challenge.UserId.Value, cancellationToken)
            : await _identityRepository.GetUserByProviderKeyAsync(_options.ProviderKey.Type, _options.ProviderKey.Name, credentialId, cancellationToken);
        if (user == null)
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        var credential = await _identityRepository.GetCredentialForUserAsync(user.Id, _options.ProviderKey.Type, _options.ProviderKey.Name, credentialId, cancellationToken);
        if (credential == null)
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        PasskeyAuthenticationVerificationResult verified;
        try
        {
            verified = await _ceremonyValidator.VerifyAuthenticationAsync(_options, challenge, credential, request.AssertionResponse, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, user.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyValidationFailed);
        }

        try
        {
            var response = await _authenticationOrchestrator.AuthenticateAsync(new AuthenticationContext(UserId: user.Id), new PasskeyAssertion(verified.CredentialId, verified.SignCount, verified.UserVerified, _options.ProviderKey), cancellationToken: cancellationToken);
            var succeeded = response.Status == MfaAuthenticationStatus.Succeeded;
            var mfaRequired = response.Status == MfaAuthenticationStatus.MfaRequired;
            var failureCode = succeeded || mfaRequired ? (AshlarFailureCode?)null : AshlarFailureCodes.PasskeyValidationFailed;
            if (failureCode is not null)
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, user.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
                return new PasskeyAuthenticationResult(false, response.User, null, failureCode, response.Status, ErrorMessage: response.ErrorMessage);
            }

            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Success, user.Id, null, request.Audit, cancellationToken);
            var summaryCredential = credential.Clone();
            summaryCredential.LastUsedAt = _timeProvider.GetUtcNow();
            var summary = ToSummary(summaryCredential);
            return new PasskeyAuthenticationResult(
                succeeded,
                response.User,
                summary,
                failureCode,
                response.Status,
                response.HandshakeToken,
                response.RequiredFactors,
                response.ErrorMessage);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, user.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyValidationFailed);
        }
    }

    public async Task<Result<PasskeyCeremonyOptions>> StartFactorAsync(StartPasskeyFactorRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.HandshakeToken) || string.IsNullOrWhiteSpace(request.FactorType))
        {
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var factorType = NormalizeFactorType(request.FactorType);
        if (factorType == null)
        {
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var handshake = await _handshakeService.GetHandshakeAsync(request.HandshakeToken, cancellationToken);
        if (handshake == null
            || handshake.IsRevoked
            || handshake.IsCompleted
            || handshake.ExpiresAt <= _timeProvider.GetUtcNow()
            || !handshake.RequiredFactors.Any(factor => string.Equals(NormalizeFactorType(factor), factorType, StringComparison.Ordinal))
            || handshake.VerifiedFactors.Any(factor => string.Equals(NormalizeFactorType(factor), factorType, StringComparison.Ordinal)))
        {
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var credentials = (await _identityRepository.ListCredentialsForUserAsync(handshake.UserId, cancellationToken: cancellationToken))
            .Where(IsPasskey)
            .Where(credential => !IsPrimaryCredential(handshake, credential))
            .ToList();
        if (credentials.Count == 0)
        {
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        var challengeValue = CreateChallenge();
        var optionsJson = _ceremonyValidator.CreateAuthenticationOptions(_options, challengeValue, credentials);
        var challenge = CreateChallengeEntity(
            AuthenticationPurpose,
            challengeValue,
            optionsJson,
            handshake.UserId,
            _tokenHasher.HashToken(request.HandshakeToken),
            factorType);
        await _challengeRepository.CreateAsync(challenge, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationStarted, SecurityEventOutcomes.Success, handshake.UserId, null, request.Audit, cancellationToken);
        return Result.Success(new PasskeyCeremonyOptions(challenge.Id, optionsJson, challenge.ExpiresAt));
    }

    public async Task<PasskeyAuthenticationResult> CompleteFactorAsync(CompletePasskeyFactorRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.HandshakeToken) || string.IsNullOrWhiteSpace(request.FactorType))
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var factorType = NormalizeFactorType(request.FactorType);
        if (factorType == null)
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var challenge = await GetChallengeAsync(request.ChallengeId, AuthenticationPurpose, cancellationToken);
        if (challenge == null
            || !challenge.UserId.HasValue
            || !string.Equals(challenge.HandshakeTokenHash, _tokenHasher.HashToken(request.HandshakeToken), StringComparison.Ordinal)
            || !string.Equals(challenge.FactorType, factorType, StringComparison.Ordinal))
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        if (!await _challengeRepository.ConsumeAsync(challenge.Id, challenge.Version, _timeProvider.GetUtcNow(), cancellationToken))
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var credentialId = request.AssertionResponse.TryGetProperty("id", out var id) ? id.GetString() : null;
        if (string.IsNullOrWhiteSpace(credentialId))
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyValidationFailed);
        }

        var user = await _identityRepository.GetUserByIdAsync(challenge.UserId.Value, cancellationToken);
        if (user == null)
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        var credential = await _identityRepository.GetCredentialForUserAsync(user.Id, _options.ProviderKey.Type, _options.ProviderKey.Name, credentialId, cancellationToken);
        if (credential == null)
        {
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        PasskeyAuthenticationVerificationResult verified;
        try
        {
            verified = await _ceremonyValidator.VerifyAuthenticationAsync(_options, challenge, credential, request.AssertionResponse, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, user.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyValidationFailed);
        }

        try
        {
            var response = await _authenticationOrchestrator.VerifyFactorAsync(
                request.HandshakeToken,
                factorType,
                new AuthenticationContext(UserId: user.Id),
                new PasskeyAssertion(verified.CredentialId, verified.SignCount, verified.UserVerified, _options.ProviderKey),
                cancellationToken);

            var succeeded = response.Status == MfaAuthenticationStatus.Succeeded;
            var incomplete = response.Status == MfaAuthenticationStatus.HandshakeIncomplete;
            if (!succeeded && !incomplete)
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, user.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
                return new PasskeyAuthenticationResult(false, response.User, null, AshlarFailureCodes.PasskeyValidationFailed, response.Status, response.HandshakeToken, response.RequiredFactors, response.ErrorMessage);
            }

            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Success, user.Id, null, request.Audit, cancellationToken);
            var summaryCredential = credential.Clone();
            summaryCredential.LastUsedAt = _timeProvider.GetUtcNow();
            return new PasskeyAuthenticationResult(
                succeeded,
                response.User,
                ToSummary(summaryCredential),
                null,
                response.Status,
                response.HandshakeToken,
                response.RequiredFactors,
                response.ErrorMessage);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, user.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
            return new PasskeyAuthenticationResult(false, null, null, AshlarFailureCodes.PasskeyValidationFailed);
        }
    }

    public async Task<IReadOnlyList<PasskeyCredentialSummary>> ListAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var credentials = await _identityRepository.ListCredentialsForUserAsync(userId, cancellationToken: cancellationToken);
        return credentials.Where(IsPasskey).Select(ToSummary).ToList().AsReadOnly();
    }

    public async Task<Result> RenameAsync(RenamePasskeyRequest request, CancellationToken cancellationToken = default)
    {
        var credential = (await _identityRepository.ListCredentialsForUserAsync(request.UserId, cancellationToken: cancellationToken)).FirstOrDefault(c => c.Id == request.CredentialId && IsPasskey(c));
        if (credential == null)
        {
            return Result.Failure(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        var metadata = ReadMetadata(credential);
        metadata.DisplayName = NormalizeDisplayName(request.DisplayName);
        credential.Metadata = JsonSerializer.Serialize(metadata, PasskeyJson.Options);
        var updated = await _identityRepository.UpdateCredentialAsync(credential, credential.Version, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyRenamed, updated ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure, request.UserId, updated ? null : AshlarFailureCodes.ConcurrencyConflict.Value, request.Audit, cancellationToken);
        return updated ? Result.Success() : Result.Failure(AshlarFailureCodes.ConcurrencyConflict);
    }

    public async Task<Result> RevokeAsync(RevokePasskeyRequest request, CancellationToken cancellationToken = default)
    {
        var credential = (await _identityRepository.ListCredentialsForUserAsync(request.UserId, cancellationToken: cancellationToken)).FirstOrDefault(c => c.Id == request.CredentialId && IsPasskey(c));
        if (credential == null)
        {
            return Result.Failure(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        credential.Status = CredentialStatus.Revoked;
        credential.RevokedAt = _timeProvider.GetUtcNow();
        var updated = await _identityRepository.UpdateCredentialAsync(credential, credential.Version, cancellationToken);
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

    private PasskeyChallenge CreateChallengeEntity(string purpose, string challenge, string optionsJson, Guid? userId, string? handshakeTokenHash = null, string? factorType = null, string? displayName = null)
    {
        var now = _timeProvider.GetUtcNow();
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = Guid.NewGuid().ToString("N"),
            Purpose = purpose,
            UserId = userId,
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
        return string.IsNullOrWhiteSpace(credential.Metadata)
            ? new PasskeyCredentialMetadata()
            : JsonSerializer.Deserialize<PasskeyCredentialMetadata>(credential.Metadata, PasskeyJson.Options) ?? new PasskeyCredentialMetadata();
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

}
