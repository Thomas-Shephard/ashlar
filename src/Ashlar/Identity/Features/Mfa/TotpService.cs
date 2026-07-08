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
    private const string EmptyActorUserIdMessage = "Actor user ID cannot be empty.";

    private readonly IUserRepository _userRepository;
    private readonly ICredentialRepository _credentialRepository;
    private readonly ICredentialService _credentialService;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly IAuthenticationProvider _provider;
    private readonly TotpOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly SecurityNotificationEmitter _notifications;
    private readonly IReadOnlyList<ISecondaryAuthenticationFactorProvider> _additionalVerificationProviders;

    public TotpService(
        IUserRepository userRepository,
        ICredentialRepository credentialRepository,
        ICredentialService credentialService,
        IAshlarTransactionProvider transactionProvider,
        IEnumerable<IAuthenticationProvider> providers,
        TotpServiceDependencies dependencies)
    {
        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _credentialRepository = credentialRepository ?? throw new ArgumentNullException(nameof(credentialRepository));
        _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        ArgumentNullException.ThrowIfNull(dependencies);
        _options = dependencies.Options.Value;
        TotpOptions.ThrowIfInvalid(_options);
        _timeProvider = dependencies.TimeProvider;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, _timeProvider);
        _notifications = new SecurityNotificationEmitter(dependencies.NotificationService);
        var providerList = providers.ToArray();
        _provider = providerList.OfType<TotpAuthenticationProvider>().FirstOrDefault()
            ?? throw new InvalidOperationException($"Required provider '{nameof(TotpAuthenticationProvider)}' not registered.");
        _additionalVerificationProviders = providerList.OfType<ISecondaryAuthenticationFactorProvider>().ToArray();
    }

    public async Task<TotpEnrollment> StartEnrollmentAsync(StartTotpEnrollmentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.ActorUserId == Guid.Empty) throw new ArgumentException(EmptyActorUserIdMessage, $"{nameof(request)}.{nameof(request.ActorUserId)}");
        var tenant = request.Tenant ?? TenantContext.Global;
        await ValidateUserTenantAsync(request.ActorUserId, tenant, request.Audit, AshlarSecurityEventTypes.TotpEnrollmentStarted, throwOnFailure: true, cancellationToken);
        var proofResult = await ValidateEnrollmentProofAsync(CreateEnrollmentProofValidationRequest(request, tenant, AshlarSecurityEventTypes.TotpEnrollmentStarted), cancellationToken);
        if (proofResult.Succeeded)
        {
            return await StartEnrollmentCoreAsync(request, validateUser: false, cancellationToken);
        }

        var failureCode = proofResult.GetFailureOr(AshlarFailureCodes.StepUpRequired).Code;
        throw new AshlarOperationException(failureCode, "Fresh verification is required for TOTP enrollment.");
    }

    public Task<TotpEnrollment> StartEnrollmentForAccountRecoveryAsync(AccountRecoveryStartTotpEnrollmentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.ThrowIfInvalid();
        return StartEnrollmentCoreAsync(
            request.UserId,
            request.Issuer,
            request.AccountName,
            request.Tenant,
            request.IncludeAllTenants,
            request.Audit,
            request.Reason,
            validateUser: true,
            cancellationToken);
    }

    private Task<TotpEnrollment> StartEnrollmentCoreAsync(StartTotpEnrollmentRequest request, bool validateUser, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return StartEnrollmentCoreAsync(
            request.ActorUserId,
            request.Issuer,
            request.AccountName,
            request.Tenant,
            includeAllTenants: false,
            request.Audit,
            reason: null,
            validateUser,
            cancellationToken);
    }

    private async Task<TotpEnrollment> StartEnrollmentCoreAsync(
        Guid userId,
        string issuer,
        string accountName,
        TenantContext? requestTenant,
        bool includeAllTenants,
        AuditContext? audit,
        string? reason,
        bool validateUser,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);

        if (validateUser)
        {
            await ValidateUserScopeAsync(userId, requestTenant, includeAllTenants, audit, AshlarSecurityEventTypes.TotpEnrollmentStarted, throwOnFailure: true, cancellationToken);
        }

        var secretBytes = RandomNumberGenerator.GetBytes(_options.SecretLengthBytes);
        var base32Secret = Base32.Encode(secretBytes);

        var uri = TotpAuthenticator.CreateOtpAuthUri("totp", base32Secret, accountName, issuer, _options.CodeDigits, _options.StepSeconds);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpEnrollmentStarted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = requestTenant?.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            Properties = CreateReasonProperties(reason)
        }, cancellationToken);

        return new TotpEnrollment(base32Secret, uri);
    }

    public async Task<Result<TotpEnrollmentCompletionResult>> CompleteEnrollmentAsync(VerifyTotpEnrollmentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.ActorUserId == Guid.Empty) throw new ArgumentException(EmptyActorUserIdMessage, $"{nameof(request)}.{nameof(request.ActorUserId)}");
        var tenant = request.Tenant ?? TenantContext.Global;
        var userResult = await ValidateUserTenantAsync(request.ActorUserId, tenant, request.Audit, AshlarSecurityEventTypes.TotpEnrollmentCompleted, throwOnFailure: false, cancellationToken);
        if (!userResult.Succeeded)
        {
            return ToEnrollmentFailureResult(userResult);
        }

        var proofResult = await ValidateEnrollmentProofAsync(CreateEnrollmentProofValidationRequest(request, tenant, AshlarSecurityEventTypes.TotpEnrollmentCompleted), cancellationToken);
        if (!proofResult.Succeeded)
        {
            return ToEnrollmentFailureResult(proofResult);
        }

        return await CompleteEnrollmentCoreAsync(request, userResult.Value, cancellationToken);
    }

    public Task<Result<TotpEnrollmentCompletionResult>> CompleteEnrollmentForAccountRecoveryAsync(AccountRecoveryCompleteTotpEnrollmentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.ThrowIfInvalid();
        return CompleteEnrollmentCoreAsync(
            request.UserId,
            request.SharedSecret,
            request.Code,
            request.Tenant,
            request.IncludeAllTenants,
            request.Audit,
            request.Reason,
            user: null,
            issueStepUpResult: false,
            cancellationToken);
    }

    private Task<Result<TotpEnrollmentCompletionResult>> CompleteEnrollmentCoreAsync(VerifyTotpEnrollmentRequest request, IUser? user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return CompleteEnrollmentCoreAsync(
            request.ActorUserId,
            request.SharedSecret,
            request.Code,
            request.Tenant,
            includeAllTenants: false,
            request.Audit,
            reason: null,
            user,
            issueStepUpResult: true,
            cancellationToken);
    }

    private async Task<Result<TotpEnrollmentCompletionResult>> CompleteEnrollmentCoreAsync(
        Guid userId,
        string sharedSecret,
        string code,
        TenantContext? requestTenant,
        bool includeAllTenants,
        AuditContext? audit,
        string? reason,
        IUser? user,
        bool issueStepUpResult,
        CancellationToken cancellationToken)
    {
        IUser enrolledUser;
        if (user == null)
        {
            var userResult = await ValidateUserScopeAsync(userId, requestTenant, includeAllTenants, audit, AshlarSecurityEventTypes.TotpEnrollmentCompleted, throwOnFailure: false, cancellationToken);
            if (!userResult.TryGetValue(out var fetchedUser))
            {
                return ToEnrollmentFailureResult(userResult);
            }

            enrolledUser = fetchedUser;
        }
        else
        {
            enrolledUser = user;
        }

        if (string.IsNullOrWhiteSpace(code))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = requestTenant?.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.EmptyCode.Value,
                Properties = CreateReasonProperties(reason)
            }, cancellationToken);
            return Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.EmptyCode);
        }

        if (string.IsNullOrWhiteSpace(sharedSecret) || sharedSecret.Length > 256)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = requestTenant?.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidSecret.Value,
                Properties = CreateReasonProperties(reason)
            }, cancellationToken);
            return Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.InvalidSecret);
        }

        if (!Base32.TryDecode(sharedSecret, out var secretBytes) || secretBytes.Length < 16)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = requestTenant?.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidSecretFormat.Value,
                Properties = CreateReasonProperties(reason)
            }, cancellationToken);
            return Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.InvalidSecretFormat);
        }

        var now = _timeProvider.GetUtcNow();

        var (verified, verifiedStep) = TotpAuthenticator.VerifyTotp(secretBytes, code, now, _options.StepSeconds, _options.CodeDigits, _options.AllowedSkewSteps);

        if (!verified)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = requestTenant?.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidCode.Value,
                Properties = CreateReasonProperties(reason)
            }, cancellationToken);
            return Result.Failure<TotpEnrollmentCompletionResult>(AshlarFailureCodes.InvalidCode);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        // Replace any existing TOTP credential for this user.
        await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);

        var assertion = new TotpAssertion(code);
        var totpCredentialMetadata = System.Text.Json.JsonSerializer.Serialize(new { LastUsedStep = verifiedStep });
        var linkResult = await _credentialService.LinkCredentialAsync(userId, assertion, _provider, sharedSecret, totpCredentialMetadata, cancellationToken);

        if (!linkResult.Succeeded)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = requestTenant?.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = linkResult.FailureCode?.Value ?? AshlarFailureCodes.LinkFailed.Value,
                Properties = CreateReasonProperties(reason)
            }, cancellationToken);
            return Result.Failure<TotpEnrollmentCompletionResult>(linkResult.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.LinkFailed));
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = requestTenant?.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            Properties = CreateReasonProperties(reason)
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _notifications.NotifyAsync(SecurityNotificationType.TotpEnrolled, enrolledUser, now, context: ToNotificationContext(audit), cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(new TotpEnrollmentCompletionResult(
            userId,
            issueStepUpResult
                ? new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, enrolledUser, FreshMfaSatisfied: true)
                {
                    StepUpSessionMarkingProof = StepUpSessionMarkingProof.Instance
                }
                : null
        ));
    }

    public async Task<bool> DisableAsync(DisableTotpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.ActorUserId == Guid.Empty) throw new ArgumentException(EmptyActorUserIdMessage, $"{nameof(request)}.{nameof(request.ActorUserId)}");
        var tenant = request.Tenant ?? TenantContext.Global;
        var proofResult = await ValidateFreshMfaProofAsync(request.ActorUserId, tenant, request.FreshMfaProof, request.CurrentSessionId, request.Audit, AshlarSecurityEventTypes.TotpDisabled, cancellationToken);
        if (!proofResult.Succeeded)
        {
            return false;
        }

        return await DisableCoreAsync(request, cancellationToken);
    }

    public Task<bool> DisableForAccountRecoveryAsync(AccountRecoveryDisableTotpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.ThrowIfInvalid();
        return DisableCoreAsync(request.UserId, request.Tenant, request.IncludeAllTenants, request.Audit, request.Reason, cancellationToken);
    }

    private Task<bool> DisableCoreAsync(DisableTotpRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return DisableCoreAsync(request.ActorUserId, request.Tenant, includeAllTenants: false, request.Audit, reason: null, cancellationToken);
    }

    private async Task<bool> DisableCoreAsync(Guid userId, TenantContext? requestTenant, bool includeAllTenants, AuditContext? audit, string? reason, CancellationToken cancellationToken)
    {
        var userResult = await ValidateUserScopeAsync(userId, requestTenant, includeAllTenants, audit, AshlarSecurityEventTypes.TotpDisabled, throwOnFailure: false, cancellationToken);
        if (!userResult.TryGetValue(out var user))
        {
            return false;
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var count = await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);
        if (count == 0) return false;

        var now = _timeProvider.GetUtcNow();
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpDisabled,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = requestTenant?.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            Properties = CreateReasonProperties(reason)
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _notifications.NotifyAsync(SecurityNotificationType.TotpDisabled, user, now, context: ToNotificationContext(audit), cancellationToken: ct);
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
        var failure = FreshVerificationProofValidator.ValidateMfaProof(userId, tenant, proof, currentSessionId, _timeProvider.GetUtcNow());
        if (failure == null)
        {
            return Result.Success();
        }

        await RecordProofFailureAsync(userId, tenant, audit, eventType, failure.Value, cancellationToken);
        return Result.Failure(failure.Value);
    }

    private async Task<Result> ValidateEnrollmentProofAsync(
        EnrollmentProofValidationRequest request,
        CancellationToken cancellationToken)
    {
        var hasExistingAdditionalVerification = await HasExistingAdditionalVerificationAsync(request.UserId, cancellationToken);
        if (hasExistingAdditionalVerification)
        {
            return await ValidateFreshMfaProofAsync(request.UserId, request.Tenant, request.MfaProof, request.CurrentSessionId, request.Audit, request.EventType, cancellationToken);
        }

        return await ValidateFreshPrimaryAuthenticationProofAsync(request.UserId, request.Tenant, request.PrimaryProof, request.CurrentSessionId, request.Audit, request.EventType, cancellationToken);
    }

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
        var failure = FreshVerificationProofValidator.ValidatePrimaryAuthenticationProof(userId, tenant, proof, currentSessionId, _timeProvider.GetUtcNow());
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

    private async Task<Result<IUser>> ValidateUserScopeAsync(
        Guid userId,
        TenantContext? tenant,
        bool includeAllTenants,
        AuditContext? audit,
        string eventType,
        bool throwOnFailure,
        CancellationToken cancellationToken)
    {
        if (!includeAllTenants)
        {
            return await ValidateUserTenantAsync(userId, tenant ?? TenantContext.Global, audit, eventType, throwOnFailure, cancellationToken);
        }

        var user = await _userRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user != null)
        {
            return Result.Success(user);
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            Audit = audit,
            Provider = _options.ProviderKey,
            FailureReason = AshlarFailureCodes.UserNotFound.Value
        }, cancellationToken);

        if (throwOnFailure)
        {
            throw new AshlarOperationException(AshlarFailureCodes.UserNotFound, "TOTP user validation failed for the requested recovery scope.");
        }

        return Result.Failure<IUser>(AshlarFailureCodes.UserNotFound);
    }

    private static AuthenticationContext? ToNotificationContext(AuditContext? audit)
    {
        if (audit == null) return new AuthenticationContext();

        return new AuthenticationContext(
            UserId: audit.ActorUserId,
            IpAddress: audit.IpAddress,
            UserAgent: audit.UserAgent,
            CorrelationId: audit.CorrelationId);
    }

    private static Dictionary<string, string>? CreateReasonProperties(string? reason)
    {
        return reason == null ? null : new Dictionary<string, string> { ["reason"] = reason };
    }
}

internal sealed record EnrollmentProofValidationRequest(
    Guid UserId,
    TenantContext Tenant,
    FreshMfaVerificationProof? MfaProof,
    FreshPrimaryAuthenticationProof? PrimaryProof,
    Guid? CurrentSessionId,
    AuditContext? Audit,
    string EventType);

internal sealed class TotpServiceDependencies(
    IOptions<TotpOptions> options,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null,
    ISecurityNotificationService? notificationService = null)
{
    public IOptions<TotpOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
