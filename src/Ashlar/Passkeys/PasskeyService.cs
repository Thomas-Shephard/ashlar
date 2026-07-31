using System.Security.Cryptography;
using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Identity.Models.Passkeys;
using Ashlar.Identity.Passkeys;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;

namespace Ashlar.Passkeys;

internal sealed class PasskeyService : IPasskeyService
{
    private sealed record AuthenticationCapability(string CredentialId, long SignCount, bool UserVerified, AuthenticationProviderKey ProviderKey) : ICredentialKeyAuthenticationAssertion, IUserVerifiedAuthenticationAssertion
    {
        public AuthenticationProviderKey ProviderIdentity => ProviderKey;
        public string CredentialKey => CredentialId;
    }

    internal static bool TryReadCapability(IAuthenticationAssertion assertion, AuthenticationProviderKey providerKey, out string credentialId, out long signCount)
    {
        if (assertion is AuthenticationCapability verified && verified.ProviderKey == providerKey)
        {
            credentialId = verified.CredentialId;
            signCount = verified.SignCount;
            return true;
        }

        credentialId = string.Empty;
        signCount = 0;
        return false;
    }

    private AuthenticationCapability CreateCapability(SucceededPasskeyAssertion ceremony) =>
        new(ceremony.Verified.CredentialId, ceremony.Verified.SignCount, ceremony.Verified.UserVerified, _options.ProviderKey);

    private const string RegistrationPurpose = IPasskeyService.RegistrationProofPurpose;
    private const string ManagementPurpose = IPasskeyService.ManagementProofPurpose;
    private const string AuthenticationPurpose = "passkey-authentication";
    private const string AuthenticationChallengeStartPurpose = "passkey-authentication-start";
    private const string MfaRegistrationProofType = "fresh-mfa";
    private const string PrimaryRegistrationProofType = "fresh-primary";
    private const string PrimaryProviderTypeMetadataKey = "primary_provider_type";
    private const string PrimaryProviderNameMetadataKey = "primary_provider_name";
    private const string PrimaryCredentialKeyMetadataKey = "primary_credential_key";
    private readonly IPasskeyCredentialStore _credentials;
    private readonly IPasskeyChallengeStore _challenges;
    private readonly ActiveSessionFreshProofValidator _proofValidator;
    private readonly IPasskeyCeremonyValidator _ceremonyValidator;
    private readonly IAuthenticationOrchestrator _authenticationOrchestrator;
    private readonly IAuthenticationHandshakeService _handshakeService;
    private readonly ISecureTokenHasher _tokenHasher;
    private readonly AuthenticationRateLimitChecker _rateLimitChecker;
    private readonly PasskeyOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventFanOutSink _securityEventSink;
    private readonly AshlarDurableTransactionProvider _transactionProvider;
    private readonly IReadOnlyList<ISecondaryAuthenticationFactorProvider> _additionalVerificationProviders;

    internal PasskeyService(
        IPasskeyCredentialStore credentials,
        IPasskeyChallengeStore challenges,
        ActiveSessionFreshProofValidator proofValidator,
        IPasskeyCeremonyValidator ceremonyValidator,
        IEnumerable<IAuthenticationProvider> providers,
        PasskeyServiceDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(dependencies);

        _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        _challenges = challenges ?? throw new ArgumentNullException(nameof(challenges));
        _proofValidator = proofValidator ?? throw new ArgumentNullException(nameof(proofValidator));
        _ceremonyValidator = ceremonyValidator ?? throw new ArgumentNullException(nameof(ceremonyValidator));
        _additionalVerificationProviders = (providers ?? throw new ArgumentNullException(nameof(providers))).OfType<ISecondaryAuthenticationFactorProvider>().ToArray();
        _authenticationOrchestrator = dependencies.AuthenticationOrchestrator;
        _handshakeService = dependencies.HandshakeService;
        _tokenHasher = dependencies.TokenHasher;
        _rateLimitChecker = new AuthenticationRateLimitChecker(dependencies.RateLimiter);
        _options = dependencies.Options.Value;
        _timeProvider = dependencies.TimeProvider;
        _securityEventSink = dependencies.SecurityEventSink;
        _transactionProvider = dependencies.TransactionProvider;
    }

    public async Task<PasskeyCeremonyOptions> StartRegistrationAsync(StartPasskeyRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!AuditActorMatches(request.Audit, request.ActorUserId))
        {
            throw new AshlarOperationException(AshlarFailureCodes.ValidationError, "Audit actor must match the authenticated actor.");
        }

        var tenant = request.Tenant ?? TenantContext.Global;
        var user = await GetAvailableRegistrationUserAsync(request.ActorUserId, tenant, cancellationToken);
        var credentials = await _credentials.ListCredentialsAsync(request.ActorUserId, cancellationToken);
        var existing = credentials
            .Where(credential => credential.ProviderType == _options.ProviderKey.Type
                && string.Equals(credential.ProviderName, _options.ProviderKey.Name, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var proofBindingResult = await ValidateRegistrationProofAsync(
            new RegistrationProofValidationRequest(
                request.ActorUserId,
                tenant,
                request.FreshMfaProof,
                request.FreshPrimaryAuthenticationProof,
                request.CurrentSessionId),
            credentials, cancellationToken);
        if (!proofBindingResult.TryGetValue(out var proofBinding))
        {
            var failure = proofBindingResult.GetFailure();
            await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationStarted, SecurityEventOutcomes.Failure, request.ActorUserId, failure.Code.Value, request.Audit, cancellationToken);
            throw new AshlarOperationException(failure.Code, "Fresh verification is required for passkey registration.");
        }

        var displayName = NormalizeDisplayName(request.DisplayName);
        var challengeValue = CreateChallenge();
        var optionsJson = _ceremonyValidator.CreateRegistrationOptions(_options, user, displayName, challengeValue, existing);
        var challenge = CreateChallengeEntity(
            RegistrationPurpose,
            challengeValue,
            optionsJson,
            request.ActorUserId,
            new ChallengeEntityMetadata(DisplayName: displayName, TenantId: tenant.TenantId, RegistrationProof: proofBinding));
        await using var transaction = await BeginTransactionAsync(cancellationToken);
        await _challenges.CreateAsync(challenge, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationStarted, SecurityEventOutcomes.Success, request.ActorUserId, null, request.Audit, cancellationToken);
        await CommitAsync(transaction, cancellationToken);
        return new PasskeyCeremonyOptions(challenge.Id, optionsJson, challenge.ExpiresAt);
    }

    public async Task<Result> CompleteRegistrationAsync(CompletePasskeyRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!AuditActorMatches(request.Audit, request.ActorUserId))
        {
            return Result.Failure(AshlarFailureCodes.ValidationError, "Audit actor must match the authenticated actor.");
        }

        var challenge = await GetChallengeAsync(request.ChallengeId, RegistrationPurpose, cancellationToken);
        if (challenge == null || challenge.UserId == null)
        {
            return Result.Failure(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        if (request.ActorUserId != challenge.UserId.Value)
        {
            return Result.Failure(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var tenant = request.Tenant ?? TenantContext.Global;
        if (tenant.TenantId != challenge.TenantId)
        {
            return Result.Failure(AshlarFailureCodes.TenantMismatch);
        }

        var proofResult = await ValidateRegistrationCompletionProofAsync(
            challenge,
            new RegistrationProofValidationRequest(
                request.ActorUserId,
                tenant,
                request.FreshMfaProof,
                request.FreshPrimaryAuthenticationProof,
                request.CurrentSessionId), cancellationToken);
        if (!proofResult.Succeeded)
        {
            return Result.Failure(proofResult.GetFailure());
        }

        var user = await _credentials.GetUserByIdAsync(challenge.UserId.Value, cancellationToken);
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

        var transaction = await BeginTransactionAsync(cancellationToken);
        var transactionDisposed = false;
        try
        {
            if (!await _challenges.ConsumeAsync(challenge.Id, challenge.Version, _timeProvider.GetUtcNow(), cancellationToken))
            {
                return Result.Failure(AshlarFailureCodes.PasskeyChallengeInvalid);
            }

            var credentialFailed = false;
            try
            {
                await _credentials.CreatePasskeyAsync(credential, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                credentialFailed = true;
            }

            if (credentialFailed)
            {
                await DisposeTransactionAsync(transaction);
                transactionDisposed = true;
                await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationCompleted, SecurityEventOutcomes.Failure, challenge.UserId, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, cancellationToken);
                return Result.Failure(AshlarFailureCodes.PasskeyValidationFailed);
            }

            await RecordAsync(AshlarSecurityEventTypes.PasskeyRegistrationCompleted, SecurityEventOutcomes.Success, challenge.UserId, null, request.Audit, cancellationToken);
            await CommitAsync(transaction, cancellationToken);
        }
        finally
        {
            if (!transactionDisposed)
            {
                await DisposeTransactionAsync(transaction);
            }
        }

        return Result.Success();
    }

    public async Task<Result<PasskeyCeremonyOptions>> StartAuthenticationAsync(StartPasskeyAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var tenant = request.Tenant ?? TenantContext.Global;
        var context = ToAuthenticationContext(request.Audit) with { TenantId = tenant.TenantId };
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
            await RecordAsync(AshlarSecurityEventTypes.AuthenticationRateLimited, SecurityEventOutcomes.Failure, request.UserId, SecurityEventFailureReasons.RateLimited, request.Audit, tenant.TenantId, cancellationToken);
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.RateLimited);
        }

        IReadOnlyList<UserCredential> credentials = [];
        if (request.UserId.HasValue)
        {
            var user = await _credentials.GetUserByIdAsync(request.UserId.Value, cancellationToken);
            if (user == null || !UserTenantOwnership.Matches(user, tenant.TenantId) || !user.CanSignIn())
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationStarted, SecurityEventOutcomes.Failure, request.UserId, AshlarFailureCodes.UserNotFoundOrUnavailable.Value, request.Audit, tenant.TenantId, cancellationToken);
                return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.UserNotFoundOrUnavailable);
            }

            credentials = await _credentials.ListPasskeysAsync(request.UserId.Value, cancellationToken);
        }

        var challengeValue = CreateChallenge();
        var optionsJson = _ceremonyValidator.CreateAuthenticationOptions(_options, challengeValue, credentials, _options.AuthenticationUserVerification);
        var challenge = CreateChallengeEntity(AuthenticationPurpose, challengeValue, optionsJson, request.UserId, new ChallengeEntityMetadata(TenantId: tenant.TenantId));
        await using var transaction = await BeginTransactionAsync(cancellationToken);
        await _challenges.CreateAsync(challenge, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationStarted, SecurityEventOutcomes.Success, request.UserId, null, request.Audit, tenant.TenantId, cancellationToken);
        await CommitAsync(transaction, cancellationToken);
        return Result.Success(new PasskeyCeremonyOptions(challenge.Id, optionsJson, challenge.ExpiresAt));
    }

    public async Task<PasskeyAuthenticationResult> CompleteAuthenticationAsync(CompletePasskeyAuthenticationRequest request, CancellationToken cancellationToken = default)
    {
        var challenge = await GetChallengeAsync(request.ChallengeId, AuthenticationPurpose, cancellationToken);
        if (challenge == null || request.TenantId != challenge.TenantId)
        {
            return FailedAuthentication(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var result = await CompleteAuthenticationWithinTransactionAsync(request, challenge, cancellationToken);
        await CommitAsync(transaction, cancellationToken);
        return result;
    }

    private async Task<PasskeyAuthenticationResult> CompleteAuthenticationWithinTransactionAsync(CompletePasskeyAuthenticationRequest request, PasskeyChallenge challenge, CancellationToken cancellationToken)
    {
        var ceremony = await CompleteAssertionCeremonyAsync(challenge, request.AssertionResponse, request.Audit, cancellationToken);
        if (ceremony is FailedPasskeyAssertion failed)
        {
            return failed.Failure;
        }

        var succeededCeremony = (SucceededPasskeyAssertion)ceremony;

        if (IsUserVerificationRequired(_options.AuthenticationUserVerification) && !succeededCeremony.Verified.UserVerified)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, request.TenantId, cancellationToken);
            return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed, succeededCeremony.User);
        }

        try
        {
            var response = await _authenticationOrchestrator.AuthenticateAsync(ToAuthenticationContext(request.Audit) with { TenantId = request.TenantId, UserId = succeededCeremony.User.Id }, CreateCapability(succeededCeremony), cancellationToken: cancellationToken);
            var succeeded = response.Status == MfaAuthenticationStatus.Succeeded;
            var mfaRequired = response.Status == MfaAuthenticationStatus.MfaRequired;
            var failureCode = succeeded || mfaRequired ? (AshlarFailureCode?)null : AshlarFailureCodes.PasskeyValidationFailed;
            if (failureCode is not null)
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, request.TenantId, cancellationToken);
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
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, request.TenantId, cancellationToken);
                return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed, succeededCeremony.User);
            }

            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Success, succeededCeremony.User.Id, null, request.Audit, request.TenantId, cancellationToken);
            var summary = ToSummary(updatedCredential);
            return new PasskeyAuthenticationResult(
                Succeeded: succeeded,
                User: response.User,
                Credential: summary,
                FailureCode: null,
                AuthenticationStatus: response.Status,
                HandshakeToken: response.HandshakeToken,
                RequiredFactors: response.RequiredFactors,
                ErrorMessage: response.ErrorMessage,
                AuthenticationResult: response);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, request.TenantId, cancellationToken);
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

        var tenant = request.Tenant ?? TenantContext.Global;
        var handshakeResult = await _handshakeService.BeginFactorChallengeAsync(
            new VerifyAuthenticationHandshakeRequest(request.HandshakeToken, factorType, Context: ToAuthenticationContext(request.Audit) with { TenantId = tenant.TenantId }),
            cancellationToken);
        if (!handshakeResult.TryGetValue(out var handshake, out var failure))
        {
            var failureCode = failure.Code == AshlarFailureCodes.RateLimitExceeded
                ? AshlarFailureCodes.RateLimitExceeded
                : AshlarFailureCodes.PasskeyChallengeInvalid;
            return Result.Failure<PasskeyCeremonyOptions>(failureCode);
        }

        if (!SecureTokenHashing.TryHashToken(_tokenHasher, request.HandshakeToken, out var handshakeTokenHash))
        {
            return Result.Failure<PasskeyCeremonyOptions>(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var credentials = (await _credentials.ListPasskeysAsync(handshake.UserId, cancellationToken))
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
            new ChallengeEntityMetadata(HandshakeTokenHash: handshakeTokenHash, FactorType: factorType, TenantId: handshake.TenantId));
        await using var transaction = await BeginTransactionAsync(cancellationToken);
        await _challenges.CreateAsync(challenge, cancellationToken);
        await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationStarted, SecurityEventOutcomes.Success, handshake.UserId, null, request.Audit, handshake.TenantId, cancellationToken);
        await CommitAsync(transaction, cancellationToken);
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

        if (request.TenantId != challenge.TenantId)
        {
            return FailedAuthentication(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var result = await CompleteFactorWithinTransactionAsync(request, challenge, factorType, cancellationToken);
        await CommitAsync(transaction, cancellationToken);
        return result;
    }

    private async Task<PasskeyAuthenticationResult> CompleteFactorWithinTransactionAsync(CompletePasskeyFactorRequest request, PasskeyChallenge challenge, string factorType, CancellationToken cancellationToken)
    {
        var ceremony = await CompleteAssertionCeremonyAsync(challenge, request.AssertionResponse, request.Audit, cancellationToken);
        if (ceremony is FailedPasskeyAssertion failed)
        {
            return failed.Failure;
        }

        var succeededCeremony = (SucceededPasskeyAssertion)ceremony;

        if (!succeededCeremony.Verified.UserVerified)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, request.TenantId, cancellationToken);
            return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed, succeededCeremony.User);
        }

        try
        {
            var response = await _authenticationOrchestrator.VerifyFactorAsync(
                request.HandshakeToken,
                factorType,
                ToAuthenticationContext(request.Audit) with { TenantId = request.TenantId, UserId = succeededCeremony.User.Id },
                CreateCapability(succeededCeremony),
                cancellationToken);

            var succeeded = response.Status == MfaAuthenticationStatus.Succeeded;
            var incomplete = response.Status == MfaAuthenticationStatus.HandshakeIncomplete;
            if (!succeeded && !incomplete)
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, request.TenantId, cancellationToken);
                return new PasskeyAuthenticationResult(
                    Succeeded: false,
                    User: response.User,
                    Credential: null,
                    FailureCode: AshlarFailureCodes.PasskeyValidationFailed,
                    AuthenticationStatus: response.Status,
                    HandshakeToken: response.HandshakeToken,
                    RequiredFactors: response.RequiredFactors,
                    ErrorMessage: response.ErrorMessage,
                    AuthenticationResult: response);
            }

            var updatedCredential = await PersistSuccessfulAssertionAsync(succeededCeremony, response.CredentialUpdatePersisted, cancellationToken);
            if (updatedCredential == null)
            {
                await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, request.TenantId, cancellationToken);
                return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed, succeededCeremony.User);
            }

            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Success, succeededCeremony.User.Id, null, request.Audit, request.TenantId, cancellationToken);
            return new PasskeyAuthenticationResult(
                Succeeded: succeeded,
                User: response.User,
                Credential: ToSummary(updatedCredential),
                FailureCode: null,
                AuthenticationStatus: response.Status,
                HandshakeToken: response.HandshakeToken,
                RequiredFactors: response.RequiredFactors,
                ErrorMessage: response.ErrorMessage,
                AuthenticationResult: response);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, succeededCeremony.User.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, request.TenantId, cancellationToken);
            return FailedAuthentication(AshlarFailureCodes.PasskeyValidationFailed);
        }
    }

    public async Task<Result<IReadOnlyList<PasskeyCredentialSummary>>> ListAsync(ListPasskeysRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Tenant);
        AshlarFailureCode? boundaryFailure;
        try
        {
            boundaryFailure = await ValidateManagementBoundaryAsync(request.ActorUserId, request.Tenant, request.CurrentSessionId, request.FreshMfaProof, request.Audit, cancellationToken);
        }
        catch
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyInventoryRead, SecurityEventOutcomes.Failure, null, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit with { ActorUserId = null }, null, CancellationToken.None);
            throw;
        }
        if (boundaryFailure != null)
        {
            await RecordAsync(AshlarSecurityEventTypes.PasskeyInventoryRead, SecurityEventOutcomes.Failure, null, boundaryFailure.Value.Value, request.Audit is null ? null : request.Audit with { ActorUserId = null }, null, CancellationToken.None);
            return Result.Failure<IReadOnlyList<PasskeyCredentialSummary>>(boundaryFailure.Value);
        }

        IReadOnlyList<UserCredential> credentials;
        try
        {
            credentials = await _credentials.ListPasskeysAsync(request.ActorUserId, cancellationToken);
        }
        catch
        {
            await RecordManagementAsync(AshlarSecurityEventTypes.PasskeyInventoryRead, SecurityEventOutcomes.Failure, AshlarFailureCodes.PasskeyValidationFailed.Value, request.Audit, request.Tenant.TenantId, request.CurrentSessionId, CancellationToken.None);
            throw;
        }

        await RecordManagementAsync(AshlarSecurityEventTypes.PasskeyInventoryRead, SecurityEventOutcomes.Success, null, request.Audit, request.Tenant.TenantId, request.CurrentSessionId, CancellationToken.None);
        return Result.Success<IReadOnlyList<PasskeyCredentialSummary>>(credentials.Select(ToSummary).ToList().AsReadOnly());
    }

    public async Task<Result> RenameAsync(RenamePasskeyRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var lookup = await FindManagedPasskeyAsync(request.ActorUserId, request.Tenant, request.CurrentSessionId, request.FreshMfaProof, request.Audit, request.CredentialId, cancellationToken);
        if (!lookup.TryGetValue(out var passkey))
        {
            return Result.Failure(lookup.GetFailure());
        }

        if (!PasskeyCredentialMetadataOperations.TryRead(passkey.Metadata, out var metadata))
        {
            return Result.Failure(AshlarFailureCodes.PasskeyValidationFailed);
        }

        metadata.DisplayName = NormalizeDisplayName(request.DisplayName);
        passkey.Metadata = JsonSerializer.Serialize(metadata, PasskeyJson.Options);
        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var updated = await _credentials.UpdatePasskeyAsync(passkey, passkey.Version, cancellationToken);
        await RecordManagementAsync(AshlarSecurityEventTypes.PasskeyRenamed, updated ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure, updated ? null : AshlarFailureCodes.ConcurrencyConflict.Value, request.Audit, request.Tenant.TenantId, request.CurrentSessionId, cancellationToken);
        await CommitAsync(transaction, cancellationToken);
        return updated ? Result.Success() : Result.Failure(AshlarFailureCodes.ConcurrencyConflict);
    }

    public async Task<Result> RevokeAsync(RevokePasskeyRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var lookup = await FindManagedPasskeyAsync(request.ActorUserId, request.Tenant, request.CurrentSessionId, request.FreshMfaProof, request.Audit, request.CredentialId, cancellationToken);
        if (!lookup.TryGetValue(out var passkey))
        {
            return Result.Failure(lookup.GetFailure());
        }

        passkey.Status = CredentialStatus.Revoked;
        passkey.RevokedAt = _timeProvider.GetUtcNow();
        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var updated = await _credentials.UpdatePasskeyAsync(passkey, passkey.Version, cancellationToken);
        await RecordManagementAsync(AshlarSecurityEventTypes.PasskeyRevoked, updated ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure, updated ? null : AshlarFailureCodes.ConcurrencyConflict.Value, request.Audit, request.Tenant.TenantId, request.CurrentSessionId, cancellationToken);
        await CommitAsync(transaction, cancellationToken);
        return updated ? Result.Success() : Result.Failure(AshlarFailureCodes.ConcurrencyConflict);
    }

    private async Task<AshlarFailureCode?> ValidateManagementBoundaryAsync(Guid actorUserId, TenantContext tenant, Guid? currentSessionId, FreshMfaVerificationProof? proof, AuditContext? audit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        if (!AuditActorMatches(audit, actorUserId))
        {
            return AshlarFailureCodes.ValidationError;
        }

        var proofFailure = await _proofValidator.ValidateAsync(actorUserId, tenant, proof, currentSessionId, ManagementPurpose, cancellationToken);
        if (proofFailure != null) return proofFailure;

        return await ActorMatchesTenantAsync(actorUserId, tenant, cancellationToken)
            ? null
            : AshlarFailureCodes.UserNotFoundOrUnavailable;
    }

    private static bool AuditActorMatches(AuditContext? audit, Guid actorUserId) =>
        audit?.ActorUserId == actorUserId;

    private async Task<Result<UserCredential>> FindManagedPasskeyAsync(
        Guid actorUserId,
        TenantContext tenant,
        Guid? currentSessionId,
        FreshMfaVerificationProof? proof,
        AuditContext? audit,
        Guid credentialId,
        CancellationToken cancellationToken)
    {
        var boundaryFailure = await ValidateManagementBoundaryAsync(actorUserId, tenant, currentSessionId, proof, audit, cancellationToken);
        if (boundaryFailure != null)
        {
            return Result.Failure<UserCredential>(boundaryFailure.Value);
        }

        var credential = await FindPasskeyAsync(actorUserId, credentialId, cancellationToken);
        return credential == null
            ? Result.Failure<UserCredential>(AshlarFailureCodes.PasskeyCredentialNotFound)
            : Result.Success(credential);
    }

    private async Task<UserCredential?> FindPasskeyAsync(Guid userId, Guid credentialId, CancellationToken cancellationToken)
    {
        var credentials = await _credentials.ListPasskeysAsync(userId, cancellationToken);
        return credentials.FirstOrDefault(c => c.Id == credentialId);
    }

    private async Task<PasskeyChallenge?> GetChallengeAsync(Guid id, string purpose, CancellationToken cancellationToken)
    {
        var challenge = await _challenges.GetAsync(id, cancellationToken);
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
        if (!await _challenges.ConsumeAsync(challenge.Id, challenge.Version, _timeProvider.GetUtcNow(), cancellationToken))
        {
            return FailedAssertion(AshlarFailureCodes.PasskeyChallengeInvalid);
        }

        var credentialId = assertionResponse.TryGetProperty("id", out var id) ? id.GetString() : null;
        if (string.IsNullOrWhiteSpace(credentialId))
        {
            return FailedAssertion(AshlarFailureCodes.PasskeyValidationFailed);
        }

        var user = challenge.UserId.HasValue
            ? await _credentials.GetUserByIdAsync(challenge.UserId.Value, cancellationToken)
            : await _credentials.GetUserByPasskeyAsync(credentialId, cancellationToken);
        if (user == null)
        {
            return FailedAssertion(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        if (!UserTenantOwnership.Matches(user, challenge.TenantId))
        {
            return FailedAssertion(AshlarFailureCodes.PasskeyCredentialNotFound);
        }

        var credential = await _credentials.GetPasskeyAsync(user.Id, credentialId, cancellationToken);
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
            await RecordAsync(AshlarSecurityEventTypes.PasskeyAuthenticationCompleted, SecurityEventOutcomes.Failure, user.Id, AshlarFailureCodes.PasskeyValidationFailed.Value, audit, challenge.TenantId, cancellationToken);
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
            var persisted = await _credentials.GetPasskeyAsync(credential.UserId, credential.ProviderKey, cancellationToken);
            return IsPersistedAssertionCurrent(persisted, assertion.Verified.SignCount, assertion.Credential.Version) ? persisted : null;
        }

        credential.LastUsedAt = _timeProvider.GetUtcNow();
        return await _credentials.UpdatePasskeyAsync(credential, assertion.Credential.Version, cancellationToken)
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

    private async Task<Result<RegistrationProofBinding>> ValidateRegistrationProofAsync(
        RegistrationProofValidationRequest request,
        IReadOnlyList<UserCredential> existingCredentials,
        CancellationToken cancellationToken)
    {
        var proofType = HasExistingAdditionalVerification(existingCredentials)
            ? MfaRegistrationProofType
            : PrimaryRegistrationProofType;
        var result = proofType == MfaRegistrationProofType
            ? await ValidateMfaRegistrationProofAsync(request, cancellationToken)
            : await ValidatePrimaryRegistrationProofAsync(request, cancellationToken);

        if (result.TryGetValue(out var binding))
        {
            return Result.Success(binding);
        }

        return Result.Failure<RegistrationProofBinding>(result.GetFailure());
    }

    private async Task<Result> ValidateRegistrationCompletionProofAsync(PasskeyChallenge challenge, RegistrationProofValidationRequest request, CancellationToken cancellationToken)
    {
        if (challenge.RegistrationProofType == MfaRegistrationProofType)
        {
            var result = await ValidateMfaRegistrationProofAsync(request, cancellationToken);
            return ValidateStoredProofBinding(challenge, result);
        }

        if (challenge.RegistrationProofType == PrimaryRegistrationProofType)
        {
            var result = await ValidatePrimaryRegistrationProofAsync(request, cancellationToken);
            return ValidateStoredProofBinding(challenge, result);
        }

        return Result.Failure(AshlarFailureCodes.StepUpRequired);
    }

    private async Task<Result<RegistrationProofBinding>> ValidateMfaRegistrationProofAsync(RegistrationProofValidationRequest request, CancellationToken cancellationToken)
    {
        var failure = await _proofValidator.ValidateAsync(request.UserId, request.Tenant, request.MfaProof, request.CurrentSessionId, RegistrationPurpose, cancellationToken);
        return failure == null
            ? Result.Success(new RegistrationProofBinding(MfaRegistrationProofType, request.MfaProof!.SessionId, request.MfaProof.ExpiresAt))
            : Result.Failure<RegistrationProofBinding>(failure.Value);
    }

    private async Task<Result<RegistrationProofBinding>> ValidatePrimaryRegistrationProofAsync(RegistrationProofValidationRequest request, CancellationToken cancellationToken)
    {
        var failure = await _proofValidator.ValidateAsync(request.UserId, request.Tenant, request.PrimaryProof, request.CurrentSessionId, RegistrationPurpose, cancellationToken);
        return failure == null
            ? Result.Success(new RegistrationProofBinding(PrimaryRegistrationProofType, request.PrimaryProof!.SessionId, request.PrimaryProof.ExpiresAt))
            : Result.Failure<RegistrationProofBinding>(failure.Value);
    }

    private static Result ValidateStoredProofBinding(PasskeyChallenge challenge, Result<RegistrationProofBinding> result)
    {
        if (!result.TryGetValue(out var binding))
        {
            return Result.Failure(result.GetFailure());
        }

        if (challenge.RegistrationProofSessionId != binding.SessionId)
        {
            return Result.Failure(AshlarFailureCodes.StepUpRequired);
        }

        if (!ProofExpiresAtMatches(challenge.RegistrationProofExpiresAt, binding.ExpiresAt))
        {
            return Result.Failure(AshlarFailureCodes.StepUpRequired);
        }

        return Result.Success();
    }

    private static bool ProofExpiresAtMatches(DateTimeOffset? storedExpiresAt, DateTimeOffset proofExpiresAt)
    {
        return storedExpiresAt.HasValue
            && Math.Abs((storedExpiresAt.Value - proofExpiresAt).TotalMilliseconds) < 1;
    }

    private bool HasExistingAdditionalVerification(IReadOnlyList<UserCredential> existingCredentials)
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var credential in existingCredentials)
        {
            if (!credential.IsAvailable(now))
            {
                continue;
            }

            var providerKey = new AuthenticationProviderKey(credential.ProviderType, credential.ProviderName);
            if (_additionalVerificationProviders.Any(provider => provider.Key == providerKey))
            {
                return true;
            }
        }

        return false;
    }

    private async Task<IUser> GetAvailableRegistrationUserAsync(Guid userId, TenantContext tenant, CancellationToken cancellationToken)
    {
        var user = await _credentials.GetUserByIdAsync(userId, cancellationToken)
            ?? throw new InvalidOperationException("User was not found.");

        if (!UserTenantOwnership.Matches(user, tenant.TenantId))
        {
            throw new InvalidOperationException("User was not found.");
        }

        if (!user.CanSignIn())
        {
            throw new InvalidOperationException("User account is unavailable.");
        }

        return user;
    }

    private async Task<bool> ActorMatchesTenantAsync(Guid actorUserId, TenantContext tenant, CancellationToken cancellationToken)
    {
        var user = await _credentials.GetUserByIdAsync(actorUserId, cancellationToken);
        return user != null && user.CanSignIn() && UserTenantOwnership.Matches(user, tenant.TenantId);
    }

    private PasskeyChallenge CreateChallengeEntity(string purpose, string challenge, string optionsJson, Guid? userId, ChallengeEntityMetadata metadata = default)
    {
        var now = _timeProvider.GetUtcNow();
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = Guid.NewGuid().ToString("N"),
            Purpose = purpose,
            UserId = userId,
            TenantId = metadata.TenantId,
            HandshakeTokenHash = metadata.HandshakeTokenHash,
            FactorType = metadata.FactorType,
            DisplayName = metadata.DisplayName,
            RegistrationProofType = metadata.RegistrationProof?.ProofType,
            RegistrationProofSessionId = metadata.RegistrationProof?.SessionId,
            RegistrationProofExpiresAt = metadata.RegistrationProof?.ExpiresAt,
            Challenge = challenge,
            OptionsJson = optionsJson,
            RelyingPartyId = _options.RelyingPartyId,
            Origin = _options.Origin,
            CreatedAt = now,
            ExpiresAt = now.Add(_options.ChallengeLifetime)
        };
    }

    private readonly record struct ChallengeEntityMetadata(string? HandshakeTokenHash = null, string? FactorType = null, string? DisplayName = null, Guid? TenantId = null, RegistrationProofBinding? RegistrationProof = null);

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
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(_options.ChallengeBytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
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
        return RecordAsync(eventType, outcome, userId, failureReason, audit, tenantId: null, cancellationToken);
    }

    private Task RecordAsync(string eventType, string outcome, Guid? userId, string? failureReason, AuditContext? audit, Guid? tenantId, CancellationToken cancellationToken)
    {
        return _securityEventSink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            Outcome = outcome,
            OccurredAt = _timeProvider.GetUtcNow(),
            TenantId = tenantId,
            UserId = userId,
            ActorUserId = audit?.ActorUserId,
            IpAddress = audit?.IpAddress,
            UserAgent = audit?.UserAgent,
            CorrelationId = audit?.CorrelationId,
            Provider = _options.ProviderKey,
            FailureReason = failureReason
        }, cancellationToken);
    }

    private Task RecordManagementAsync(string eventType, string outcome, string? failureReason, AuditContext audit,
        Guid? tenantId, Guid sessionId, CancellationToken cancellationToken)
    {
        return _securityEventSink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            Outcome = outcome,
            OccurredAt = _timeProvider.GetUtcNow(),
            TenantId = tenantId,
            UserId = audit.ActorUserId,
            ActorUserId = audit.ActorUserId,
            SessionId = sessionId,
            IpAddress = audit.IpAddress,
            UserAgent = audit.UserAgent,
            CorrelationId = audit.CorrelationId,
            Provider = _options.ProviderKey,
            FailureReason = failureReason
        }, cancellationToken);
    }

    private Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken)
    {
        return _transactionProvider.BeginTransactionAsync(cancellationToken);
    }

    private static Task CommitAsync(IAshlarTransaction transaction, CancellationToken cancellationToken) =>
        transaction.CommitAsync(cancellationToken);

    private static ValueTask DisposeTransactionAsync(IAshlarTransaction transaction) => transaction.DisposeAsync();

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
    PasskeyAuthenticationVerificationResult Verified) : IPasskeyAssertionCompletion;

internal sealed record RegistrationProofValidationRequest(
    Guid UserId,
    TenantContext Tenant,
    FreshMfaVerificationProof? MfaProof,
    FreshPrimaryAuthenticationProof? PrimaryProof,
    Guid? CurrentSessionId);

internal sealed record RegistrationProofBinding(string ProofType, Guid SessionId, DateTimeOffset ExpiresAt);

internal sealed class PasskeyServiceDependencies(
    IOptions<PasskeyOptions> options,
    IAuthenticationOrchestrator authenticationOrchestrator,
    IAuthenticationHandshakeService handshakeService,
    ISecureTokenHasher tokenHasher,
    IAuthenticationRateLimiter rateLimiter,
    PasskeyServiceInfrastructure infrastructure)
{
    private PasskeyServiceInfrastructure Infrastructure { get; } = infrastructure ?? throw new ArgumentNullException(nameof(infrastructure));
    public IOptions<PasskeyOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));
    public IAuthenticationOrchestrator AuthenticationOrchestrator { get; } = authenticationOrchestrator ?? throw new ArgumentNullException(nameof(authenticationOrchestrator));
    public IAuthenticationHandshakeService HandshakeService { get; } = handshakeService ?? throw new ArgumentNullException(nameof(handshakeService));
    public ISecureTokenHasher TokenHasher { get; } = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));
    public IAuthenticationRateLimiter RateLimiter { get; } = rateLimiter ?? throw new ArgumentNullException(nameof(rateLimiter));
    public TimeProvider TimeProvider => Infrastructure.TimeProvider ?? TimeProvider.System;
    public SecurityEventFanOutSink SecurityEventSink => Infrastructure.SecurityEventSink;
    public AshlarDurableTransactionProvider TransactionProvider => Infrastructure.TransactionProvider;
}

internal sealed class PasskeyServiceInfrastructure(
    TimeProvider? timeProvider,
    SecurityEventFanOutSink securityEventSink,
    AshlarDurableTransactionProvider transactionProvider)
{
    public TimeProvider? TimeProvider { get; } = timeProvider;
    public SecurityEventFanOutSink SecurityEventSink { get; } = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
    public AshlarDurableTransactionProvider TransactionProvider { get; } = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
}
