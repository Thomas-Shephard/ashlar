using System.Security.Cryptography;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Security;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Mfa;

internal sealed class TotpService : ITotpService
{
    internal const string ProofPurpose = ITotpService.ManagementProofPurpose;
    private const string EmptyActorUserIdMessage = "Actor user ID cannot be empty.";

    private readonly IUserRepository _userRepository;
    private readonly ICredentialRepository _credentialRepository;
    private readonly ICredentialService _credentialService;
    private readonly AshlarDurableTransactionProvider _transactionProvider;
    private readonly IAuthenticationProvider _provider;
    private readonly TotpOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly SecurityNotificationEmitter _notifications;
    private readonly IReadOnlyList<ISecondaryAuthenticationFactorProvider> _additionalVerificationProviders;
    private readonly IAccountSecurityOperationAuthorizer _authorizer;
    private readonly ActiveSessionFreshProofValidator _proofValidator;

    public TotpService(
        IUserRepository userRepository,
        ICredentialRepository credentialRepository,
        ICredentialService credentialService,
        AshlarDurableTransactionProvider transactionProvider,
        IEnumerable<IAuthenticationProvider> providers,
        IAccountSecurityOperationAuthorizer authorizer,
        TotpServiceDependencies dependencies)
    {
        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _credentialRepository = credentialRepository ?? throw new ArgumentNullException(nameof(credentialRepository));
        _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        ArgumentNullException.ThrowIfNull(dependencies);
        _authorizer = authorizer ?? throw new ArgumentNullException(nameof(authorizer));
        _proofValidator = dependencies.ProofValidator;
        _options = dependencies.Options.Value;
        TotpOptions.ThrowIfInvalid(_options);
        _timeProvider = dependencies.TimeProvider;
        _securityEvents = new SecurityEventEmitter(DurableSecurityMutationComposition.Require(dependencies.SecurityEventSink, transactionProvider, "TOTP mutations", userRepository, credentialRepository), _timeProvider);
        _notifications = new SecurityNotificationEmitter(dependencies.NotificationService);
        var providerList = providers.ToArray();
        _provider = providerList.OfType<TotpAuthenticationProvider>().FirstOrDefault()
            ?? throw new InvalidOperationException($"Required provider '{nameof(TotpAuthenticationProvider)}' not registered.");
        _additionalVerificationProviders = providerList.OfType<ISecondaryAuthenticationFactorProvider>().ToArray();
    }

    public async Task<TotpEnrollment> StartEnrollmentAsync(StartTotpEnrollmentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.AccountName);
        var tenant = ValidateSelfServiceRequest(request.ActorUserId, request.Tenant, request.Audit, nameof(request));
        if (!HasExactlyOneEnrollmentProof(request.FreshMfaProof, request.FreshPrimaryAuthenticationProof))
        {
            await RecordProofFailureAsync(request.ActorUserId, tenant, request.Audit, AshlarSecurityEventTypes.TotpEnrollmentStarted, AshlarFailureCodes.StepUpRequired, cancellationToken);
            throw new AshlarOperationException(AshlarFailureCodes.StepUpRequired, "Exactly one fresh verification proof is required.");
        }
        var proofResult = await ValidateEnrollmentProofAsync(CreateEnrollmentProofValidationRequest(request, tenant, AshlarSecurityEventTypes.TotpEnrollmentStarted), AccountSecurityOperation.StartTotpEnrollment, cancellationToken);
        if (!proofResult.Succeeded)
        {
            var failureCode = proofResult.GetFailureOr(AshlarFailureCodes.StepUpRequired).Code;
            throw new AshlarOperationException(failureCode, "Fresh verification is required for TOTP enrollment.");
        }

        await ValidateUserTenantAsync(request.ActorUserId, tenant, request.Audit, AshlarSecurityEventTypes.TotpEnrollmentStarted, throwOnFailure: true, cancellationToken);
        if (!await HasRequiredEnrollmentProofTypeAsync(request.ActorUserId, request.FreshMfaProof != null, cancellationToken))
        {
            await RecordProofFailureAsync(request.ActorUserId, tenant, request.Audit, AshlarSecurityEventTypes.TotpEnrollmentStarted, AshlarFailureCodes.StepUpRequired, cancellationToken);
            throw new AshlarOperationException(AshlarFailureCodes.StepUpRequired, "Fresh MFA verification is required when an additional-verification factor already exists.");
        }
        return await StartEnrollmentCoreAsync(request, cancellationToken);
    }

    private async Task<TotpEnrollment> StartEnrollmentCoreAsync(StartTotpEnrollmentRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var secretBytes = RandomNumberGenerator.GetBytes(_options.SecretLengthBytes);
        var base32Secret = Base32.Encode(secretBytes);
        var uri = TotpAuthenticator.CreateOtpAuthUri("totp", base32Secret, request.AccountName, request.Issuer, _options.CodeDigits, _options.StepSeconds);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpEnrollmentStarted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = request.ActorUserId,
            TenantId = request.Tenant.TenantId,
            Audit = request.Audit,
            Provider = _options.ProviderKey
        }, cancellationToken);

        return new TotpEnrollment(base32Secret, uri);
    }

    public async Task<Result<TotpEnrollmentCompletionResult>> CompleteEnrollmentAsync(VerifyTotpEnrollmentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Code))
            return Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.EmptyCode);
        if (string.IsNullOrWhiteSpace(request.SharedSecret) || request.SharedSecret.Length > 256)
            return Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.InvalidSecret);
        var tenant = ValidateSelfServiceRequest(request.ActorUserId, request.Tenant, request.Audit, nameof(request));
        if (!HasExactlyOneEnrollmentProof(request.FreshMfaProof, request.FreshPrimaryAuthenticationProof))
        {
            await RecordProofFailureAsync(request.ActorUserId, tenant, request.Audit, AshlarSecurityEventTypes.TotpEnrollmentCompleted, AshlarFailureCodes.StepUpRequired, cancellationToken);
            return Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.StepUpRequired);
        }
        var proofResult = await ValidateEnrollmentProofAsync(CreateEnrollmentProofValidationRequest(request, tenant, AshlarSecurityEventTypes.TotpEnrollmentCompleted), AccountSecurityOperation.CompleteTotpEnrollment, cancellationToken);
        if (!proofResult.Succeeded)
        {
            return ToEnrollmentFailureResult(proofResult);
        }

        var userResult = await ValidateUserTenantAsync(request.ActorUserId, tenant, request.Audit, AshlarSecurityEventTypes.TotpEnrollmentCompleted, throwOnFailure: false, cancellationToken);
        if (!userResult.TryGetValue(out _))
        {
            return ToEnrollmentFailureResult(userResult);
        }

        Result<TotpEnrollmentCompletionResult> completionResult;
        await using (var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken))
        {
            await _credentialRepository.AcquireUserMutationLockAsync(request.ActorUserId, cancellationToken);
            var lockedUserResult = await ValidateUserTenantAsync(request.ActorUserId, tenant, request.Audit,
                AshlarSecurityEventTypes.TotpEnrollmentCompleted, throwOnFailure: false, cancellationToken);
            if (!lockedUserResult.TryGetValue(out var user))
            {
                completionResult = ToEnrollmentFailureResult(lockedUserResult);
            }
            else if (!await HasRequiredEnrollmentProofTypeAsync(request.ActorUserId, request.FreshMfaProof != null, cancellationToken))
            {
                completionResult = Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.StepUpRequired);
            }
            else
            {
                completionResult = await CompleteEnrollmentCoreAsync(new TotpEnrollmentCompletionContext
                {
                    UserId = request.ActorUserId,
                    SharedSecret = request.SharedSecret,
                    Code = request.Code,
                    Tenant = request.Tenant,
                    Audit = request.Audit,
                    User = user,
                    CurrentSessionId = request.CurrentSessionId
                }, transaction, cancellationToken);
            }

            if (completionResult.Succeeded)
                return completionResult;
        }

        await RecordEnrollmentCompletionFailureAsync(request, completionResult.GetFailureOr(AshlarFailureCodes.ValidationError).Code, cancellationToken);
        return completionResult;
    }

    private async Task<Result<TotpEnrollmentCompletionResult>> CompleteEnrollmentCoreAsync(
        TotpEnrollmentCompletionContext context,
        IAshlarTransaction transaction,
        CancellationToken cancellationToken)
    {
        if (!Base32.TryDecode(context.SharedSecret, out var secretBytes) || secretBytes.Length < 16)
            return Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.InvalidSecretFormat);

        var now = _timeProvider.GetUtcNow();

        var (verified, verifiedStep) = TotpAuthenticator.VerifyTotp(secretBytes, context.Code, now, _options.StepSeconds, _options.CodeDigits, _options.AllowedSkewSteps);

        if (!verified)
            return Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.InvalidCode);

        // Replace any existing TOTP credential for this user.
        await _credentialRepository.RevokeCredentialsAsync(context.UserId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);

        var assertion = new TotpAssertion(context.Code);
        var totpCredentialMetadata = System.Text.Json.JsonSerializer.Serialize(new { LastUsedStep = verifiedStep });
        var linkResult = await _credentialService.LinkCredentialAsync(
            new InternalCredentialLinkRequest(context.UserId, assertion, _provider, context.SharedSecret, totpCredentialMetadata, context.Audit, context.Tenant.TenantId),
            cancellationToken);

        if (!linkResult.Succeeded)
            return Result.Failure<TotpEnrollmentCompletionResult>(linkResult.GetFailureOr(AshlarFailureCodes.LinkFailed));

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = context.UserId,
            TenantId = context.Tenant.TenantId,
            Audit = context.Audit,
            Provider = _options.ProviderKey
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _notifications.NotifyAsync(SecurityNotificationType.TotpEnrolled, context.User, now, context: ToNotificationContext(context.Audit), cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(new TotpEnrollmentCompletionResult(
            context.UserId,
            new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, context.User, FreshMfaSatisfied: true)
            {
                StepUpSessionMarkingProof = StepUpSessionMarkingProof.Create(
                    context.User.Id, context.CurrentSessionId, _options.ProviderKey, AuthenticationFactorTypes.Totp, now)
            }));
    }

    private Task RecordEnrollmentCompletionFailureAsync(
        VerifyTotpEnrollmentRequest request,
        AshlarFailureCode failureCode,
        CancellationToken cancellationToken) =>
        _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = request.ActorUserId,
            TenantId = request.Tenant.TenantId,
            Audit = request.Audit,
            Provider = _options.ProviderKey,
            FailureReason = failureCode.Value
        }, cancellationToken);

    public async Task<bool> DisableAsync(DisableTotpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var tenant = ValidateSelfServiceRequest(request.ActorUserId, request.Tenant, request.Audit, nameof(request));
        var proofResult = await ValidateFreshMfaProofAsync(request.ActorUserId, tenant, request.FreshMfaProof, request.CurrentSessionId, request.Audit, AshlarSecurityEventTypes.TotpDisabled, cancellationToken);
        if (!proofResult.Succeeded)
        {
            return false;
        }

        if (!await AuthorizeAsync(request.ActorUserId, tenant, request.CurrentSessionId, AccountSecurityOperation.DisableTotp, cancellationToken))
        {
            await RecordProofFailureAsync(request.ActorUserId, tenant, request.Audit, AshlarSecurityEventTypes.TotpDisabled, AshlarFailureCodes.ValidationError, cancellationToken);
            return false;
        }

        return await DisableCoreAsync(request, cancellationToken);
    }

    private static TenantContext ValidateSelfServiceRequest(Guid actorUserId, TenantContext? tenant, AuditContext? audit, string parameterName)
    {
        if (actorUserId == Guid.Empty) throw new ArgumentException(EmptyActorUserIdMessage, $"{parameterName}.ActorUserId");
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentNullException.ThrowIfNull(audit);
        if (audit.ActorUserId != actorUserId) throw new ArgumentException("Audit actor must match the authenticated actor.", $"{parameterName}.{nameof(audit)}");
        return tenant;
    }

    private static bool HasExactlyOneEnrollmentProof(FreshMfaVerificationProof? mfaProof,
        FreshPrimaryAuthenticationProof? primaryProof) => (mfaProof is null) != (primaryProof is null);

    private async Task<bool> DisableCoreAsync(DisableTotpRequest request, CancellationToken cancellationToken)
    {
        var userResult = await ValidateUserTenantAsync(
            request.ActorUserId,
            request.Tenant,
            request.Audit,
            AshlarSecurityEventTypes.TotpDisabled,
            throwOnFailure: false,
            cancellationToken);
        if (!userResult.TryGetValue(out _))
        {
            return false;
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        await _credentialRepository.AcquireUserMutationLockAsync(request.ActorUserId, cancellationToken);
        var lockedUserResult = await ValidateUserTenantAsync(
            request.ActorUserId,
            request.Tenant,
            request.Audit,
            AshlarSecurityEventTypes.TotpDisabled,
            throwOnFailure: false,
            cancellationToken);
        if (!lockedUserResult.TryGetValue(out var user))
        {
            await transaction.CommitAsync(cancellationToken);
            return false;
        }

        var count = await _credentialRepository.RevokeCredentialsAsync(request.ActorUserId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);
        if (count == 0) return false;

        var now = _timeProvider.GetUtcNow();
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpDisabled,
            Outcome = SecurityEventOutcomes.Success,
            UserId = request.ActorUserId,
            TenantId = request.Tenant.TenantId,
            Audit = request.Audit,
            Provider = _options.ProviderKey
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _notifications.NotifyAsync(SecurityNotificationType.TotpDisabled, user, now, context: ToNotificationContext(request.Audit), cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    private async Task<Result> ValidateFreshMfaProofAsync(
        Guid userId,
        TenantContext tenant,
        FreshMfaVerificationProof? proof,
        Guid? currentSessionId,
        AuditContext? audit,
        string eventType,
        CancellationToken cancellationToken)
    {
        var failure = await _proofValidator.ValidateAsync(userId, tenant, proof, currentSessionId, ProofPurpose, cancellationToken);
        if (failure == null)
        {
            return Result.Success();
        }

        await RecordProofFailureAsync(userId, tenant, audit, eventType, failure.Value, cancellationToken);
        return Result.Failure(failure.Value);
    }

    private async Task<Result> ValidateEnrollmentProofAsync(
        EnrollmentProofValidationRequest request,
        AccountSecurityOperation operation,
        CancellationToken cancellationToken)
    {
        Result proofResult;
        if (request.MfaProof != null)
        {
            proofResult = await ValidateFreshMfaProofAsync(request.UserId, request.Tenant, request.MfaProof, request.CurrentSessionId, request.Audit, request.EventType, cancellationToken);
        }
        else
        {
            proofResult = await ValidateFreshPrimaryAuthenticationProofAsync(request.UserId, request.Tenant, request.PrimaryProof, request.CurrentSessionId, request.Audit, request.EventType, cancellationToken);
        }

        if (!proofResult.Succeeded)
        {
            return proofResult;
        }

        if (!await AuthorizeAsync(request.UserId, request.Tenant, request.CurrentSessionId, operation, cancellationToken))
        {
            await RecordProofFailureAsync(request.UserId, request.Tenant, request.Audit, request.EventType, AshlarFailureCodes.ValidationError, cancellationToken);
            return Result.Failure(AshlarFailureCodes.ValidationError);
        }

        return Result.Success();
    }

    private async Task<bool> HasRequiredEnrollmentProofTypeAsync(Guid userId, bool hasMfaProof, CancellationToken cancellationToken) =>
        await HasExistingAdditionalVerificationAsync(userId, cancellationToken) == hasMfaProof;

    private ValueTask<bool> AuthorizeAsync(Guid actorUserId, TenantContext tenant, Guid currentSessionId,
        AccountSecurityOperation operation, CancellationToken cancellationToken) =>
        _authorizer.AuthorizeAsync(new AccountSecurityAuthorizationContext(
            actorUserId, tenant, actorUserId, tenant, false, operation, Provider: _options.ProviderKey,
            CurrentSessionId: currentSessionId), cancellationToken);

    private static EnrollmentProofValidationRequest CreateEnrollmentProofValidationRequest(StartTotpEnrollmentRequest request, TenantContext tenant, string eventType)
    {
        return new EnrollmentProofValidationRequest(
            request.ActorUserId,
            tenant,
            request.FreshMfaProof,
            request.FreshPrimaryAuthenticationProof,
            request.CurrentSessionId,
            request.Audit,
            eventType);
    }

    private static EnrollmentProofValidationRequest CreateEnrollmentProofValidationRequest(VerifyTotpEnrollmentRequest request, TenantContext tenant, string eventType)
    {
        return new EnrollmentProofValidationRequest(
            request.ActorUserId,
            tenant,
            request.FreshMfaProof,
            request.FreshPrimaryAuthenticationProof,
            request.CurrentSessionId,
            request.Audit,
            eventType);
    }

    private async Task<Result> ValidateFreshPrimaryAuthenticationProofAsync(
        Guid userId,
        TenantContext tenant,
        FreshPrimaryAuthenticationProof? proof,
        Guid? currentSessionId,
        AuditContext? audit,
        string eventType,
        CancellationToken cancellationToken)
    {
        var failure = await _proofValidator.ValidateAsync(userId, tenant, proof, currentSessionId, ProofPurpose, cancellationToken);
        if (failure == null)
        {
            return Result.Success();
        }

        await RecordProofFailureAsync(userId, tenant, audit, eventType, failure.Value, cancellationToken);
        return Result.Failure(failure.Value);
    }

    private Task RecordProofFailureAsync(
        Guid userId,
        TenantContext tenant,
        AuditContext? audit,
        string eventType,
        AshlarFailureCode failure,
        CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            FailureReason = failure.Value
        }, cancellationToken);
    }

    private async Task<bool> HasExistingAdditionalVerificationAsync(Guid userId, CancellationToken cancellationToken)
    {
        var credentials = await _credentialRepository.ListCredentialsForUserAsync(userId, activeOnly: true, cancellationToken);
        var now = _timeProvider.GetUtcNow();
        foreach (var credential in credentials)
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

    private static Result<TotpEnrollmentCompletionResult> ToEnrollmentFailureResult<T>(Result<T> result)
    {
        return Result.Failure<TotpEnrollmentCompletionResult>(result.GetFailureOr(AshlarFailureCodes.ValidationError));
    }

    private static Result<TotpEnrollmentCompletionResult> ToEnrollmentFailureResult(Result result)
    {
        return Result.Failure<TotpEnrollmentCompletionResult>(result.GetFailureOr(AshlarFailureCodes.ValidationError));
    }

    private async Task<Result<IUser>> ValidateUserTenantAsync(
        Guid userId,
        TenantContext tenant,
        AuditContext? audit,
        string eventType,
        bool throwOnFailure,
        CancellationToken cancellationToken)
    {
        var result = await UserTenantValidator.GetUserInTenantAsync(_userRepository, userId, tenant, cancellationToken);
        if (result.Succeeded)
        {
            return result;
        }

        var failureCode = result.GetFailureOr(AshlarFailureCodes.ValidationError).Code;
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            FailureReason = failureCode.Value
        }, cancellationToken);

        if (throwOnFailure)
        {
            throw new AshlarOperationException(result.GetFailureOr(AshlarFailureCodes.ValidationError).Code, "TOTP user validation failed for the requested tenant.");
        }

        return result;
    }

    private static AuthenticationContext ToNotificationContext(AuditContext audit)
    {
        return new AuthenticationContext(
            UserId: audit.ActorUserId,
            IpAddress: audit.IpAddress,
            UserAgent: audit.UserAgent,
            CorrelationId: audit.CorrelationId);
    }
}

internal sealed record EnrollmentProofValidationRequest(
    Guid UserId,
    TenantContext Tenant,
    FreshMfaVerificationProof? MfaProof,
    FreshPrimaryAuthenticationProof? PrimaryProof,
    Guid CurrentSessionId,
    AuditContext Audit,
    string EventType);

internal sealed class TotpEnrollmentCompletionContext
{
    public required Guid UserId { get; init; }
    public required string SharedSecret { get; init; }
    public required string Code { get; init; }
    public required TenantContext Tenant { get; init; }
    public required AuditContext Audit { get; init; }
    public required IUser User { get; init; }
    public required Guid CurrentSessionId { get; init; }
}

internal sealed class TotpServiceDependencies(
    IOptions<TotpOptions> options,
    ActiveSessionFreshProofValidator proofValidator,
    TimeProvider? timeProvider = null,
    SecurityEventFanOutSink? securityEventSink = null,
    ISecurityNotificationService? notificationService = null)
{
    public IOptions<TotpOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));
    public ActiveSessionFreshProofValidator ProofValidator { get; } = proofValidator ?? throw new ArgumentNullException(nameof(proofValidator));
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;
    public SecurityEventFanOutSink? SecurityEventSink { get; } = securityEventSink;
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
