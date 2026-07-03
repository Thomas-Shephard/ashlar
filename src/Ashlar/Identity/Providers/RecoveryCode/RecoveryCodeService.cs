using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Implements services for managing user recovery codes.
/// </summary>
public sealed class RecoveryCodeService : IRecoveryCodeService
{
    private const string EmptyUserIdMessage = "User ID cannot be empty.";

    private readonly IUserRepository _userRepository;
    private readonly ICredentialRepository _credentialRepository;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly Security.Hashing.PasswordHasherSelector _hasherSelector;
    private readonly RecoveryCodeOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly SecurityNotificationEmitter _notifications;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="userRepository">Stores and retrieves users.</param>
    /// <param name="credentialRepository">Stores and retrieves credentials.</param>
    /// <param name="transactionProvider">Coordinates credential writes with committed audit and notification callbacks.</param>
    /// <param name="hasherSelector">Selects the password hasher used to store recovery-code secret fragments.</param>
    /// <param name="dependencies">Options and operational dependencies used by recovery-code flows.</param>
    public RecoveryCodeService(
        IUserRepository userRepository,
        ICredentialRepository credentialRepository,
        IAshlarTransactionProvider transactionProvider,
        Security.Hashing.PasswordHasherSelector hasherSelector,
        RecoveryCodeServiceDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(userRepository);
        ArgumentNullException.ThrowIfNull(credentialRepository);
        ArgumentNullException.ThrowIfNull(transactionProvider);
        ArgumentNullException.ThrowIfNull(hasherSelector);
        ArgumentNullException.ThrowIfNull(dependencies);
        ArgumentNullException.ThrowIfNull(dependencies.Options.Value);

        _userRepository = userRepository;
        _credentialRepository = credentialRepository;
        _transactionProvider = transactionProvider;
        _hasherSelector = hasherSelector;
        _options = dependencies.Options.Value;
        _timeProvider = dependencies.TimeProvider;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, _timeProvider);
        _notifications = new SecurityNotificationEmitter(dependencies.NotificationService);
    }

    /// <inheritdoc />
    public async Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesAsync(Guid userId, RecoveryCodeGenerationRequest? request = null, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException(EmptyUserIdMessage, nameof(userId));
        }

        request ??= new RecoveryCodeGenerationRequest();
        var tenant = request.Tenant ?? TenantContext.Global;
        var proofResult = await ValidateFreshMfaProofAsync(userId, tenant, request.FreshMfaProof, request.CurrentSessionId, request.Audit, AshlarSecurityEventTypes.RecoveryCodesGenerated, cancellationToken);
        if (!proofResult.Succeeded)
        {
            return Result.Failure<IReadOnlyList<string>>(proofResult.GetFailureOr(AshlarFailureCodes.StepUpRequired));
        }

        return await GenerateRecoveryCodesCoreAsync(userId, request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesPrivilegedAsync(Guid userId, RecoveryCodeGenerationRequest? request = null, CancellationToken cancellationToken = default)
    {
        request ??= new RecoveryCodeGenerationRequest();
        RequirePrivilegedAudit(request.Audit);
        return GenerateRecoveryCodesCoreAsync(userId, request, cancellationToken);
    }

    private async Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesCoreAsync(Guid userId, RecoveryCodeGenerationRequest request, CancellationToken cancellationToken)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException(EmptyUserIdMessage, nameof(userId));
        }

        var tenant = request.Tenant ?? TenantContext.Global;

        var userResult = await ValidateUserTenantAsync(userId, tenant, request.Audit, AshlarSecurityEventTypes.RecoveryCodesGenerated, cancellationToken);
        if (!userResult.TryGetValue(out var user))
        {
            return Result.Failure<IReadOnlyList<string>>(userResult.GetFailureOr(AshlarFailureCodes.UserNotFoundOrUnavailable));
        }

        var codeCount = request.CodeCount ?? _options.CodeCount;
        if (codeCount <= 0 || codeCount > _options.CodeCount * 2)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidCodeCount.Value
            }, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidCodeCount);
        }

        if (_options.CodeLength <= 0 || _options.GroupSize <= 0)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidConfiguration.Value
            }, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidConfiguration);
        }

        var expiresAfter = request.ExpiresAfter ?? _options.ExpiresAfter;
        if (expiresAfter.HasValue && expiresAfter.Value <= TimeSpan.Zero)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidExpiry.Value
            }, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidExpiry);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        // Revoke existing recovery codes if requested
        if (request.ReplaceExisting)
        {
            await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);
        }

        var rawCodes = new List<string>();
        var now = _timeProvider.GetUtcNow();
        var expiresAt = expiresAfter.HasValue ? now.Add(expiresAfter.Value) : (DateTimeOffset?)null;

        for (int i = 0; i < codeCount; i++)
        {
            var idCode = RecoveryCodeGenerator.GenerateCode(5, 5);
            var secretCode = RecoveryCodeGenerator.GenerateCode(_options.CodeLength, _options.GroupSize);
            var rawCode = $"{idCode}-{secretCode}";
            rawCodes.Add(rawCode);

            var hashedCode = PasswordCredentialHashing.HashToBase64(_hasherSelector, secretCode);

            var credential = new UserCredential
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ProviderType = _options.ProviderKey.Type,
                ProviderName = _options.ProviderKey.Name,
                ProviderKey = $"{userId:N}-{idCode}",
                CredentialValue = hashedCode,
                Purpose = "recovery-code",
                Status = CredentialStatus.Active,
                CreatedAt = now,
                Version = Guid.NewGuid().ToString("N"),
                ExpiresAt = expiresAt
            };

            await _credentialRepository.CreateCredentialAsync(credential, cancellationToken);
        }

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                Properties = new Dictionary<string, string>
                {
                    ["count"] = codeCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
                }
            }, ct);

            await _notifications.NotifyAsync(SecurityNotificationType.RecoveryCodesGenerated, user, now, context: ToNotificationContext(request.Audit), metadata: new Dictionary<string, string>
            {
                ["count"] = codeCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
            }, cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success<IReadOnlyList<string>>(rawCodes);
    }

    /// <inheritdoc />
    public async Task<int> RevokeRecoveryCodesAsync(Guid userId, RevokeRecoveryCodesRequest? request = null, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException(EmptyUserIdMessage, nameof(userId));
        }

        request ??= new RevokeRecoveryCodesRequest();
        var tenant = request.Tenant ?? TenantContext.Global;
        var proofResult = await ValidateFreshMfaProofAsync(userId, tenant, request.FreshMfaProof, request.CurrentSessionId, request.Audit, AshlarSecurityEventTypes.RecoveryCodesRevoked, cancellationToken);
        if (!proofResult.Succeeded)
        {
            return 0;
        }

        return await RevokeRecoveryCodesCoreAsync(userId, request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<int> RevokeRecoveryCodesPrivilegedAsync(Guid userId, RevokeRecoveryCodesRequest? request = null, CancellationToken cancellationToken = default)
    {
        request ??= new RevokeRecoveryCodesRequest();
        RequirePrivilegedAudit(request.Audit);
        return RevokeRecoveryCodesCoreAsync(userId, request, cancellationToken);
    }

    private async Task<int> RevokeRecoveryCodesCoreAsync(Guid userId, RevokeRecoveryCodesRequest request, CancellationToken cancellationToken)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException(EmptyUserIdMessage, nameof(userId));
        }
        var tenant = request.Tenant ?? TenantContext.Global;

        var userResult = await ValidateUserTenantAsync(userId, tenant, request.Audit, AshlarSecurityEventTypes.RecoveryCodesRevoked, cancellationToken);
        if (!userResult.Succeeded)
        {
            return 0;
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var count = await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RecoveryCodesRevoked,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = request.Audit,
            Provider = _options.ProviderKey,
            Properties = CreateRevocationProperties(count, request.Reason)
        }, ct));

        await transaction.CommitAsync(cancellationToken);

        return count;
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
        AshlarFailureCode? failure = null;
        if (userId == Guid.Empty || proof == null)
        {
            failure = AshlarFailureCodes.StepUpRequired;
        }
        else if (proof.UserId != userId)
        {
            failure = AshlarFailureCodes.TenantMismatch;
        }
        else if (proof.TenantId != tenant.TenantId)
        {
            failure = AshlarFailureCodes.TenantMismatch;
        }
        else if (currentSessionId == null || proof.SessionId != currentSessionId.Value)
        {
            failure = AshlarFailureCodes.StepUpRequired;
        }
        else if (proof.ExpiresAt <= _timeProvider.GetUtcNow())
        {
            failure = AshlarFailureCodes.StepUpExpired;
        }

        if (failure == null)
        {
            return Result.Success();
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            FailureReason = failure.Value.Value
        }, cancellationToken);

        return Result.Failure(failure.Value);
    }

    private static void RequirePrivilegedAudit(AuditContext? audit)
    {
        if (audit == null)
        {
            throw new ArgumentException("Privileged recovery-code management requires audit context.", nameof(audit));
        }
    }

    private static Dictionary<string, string> CreateRevocationProperties(int count, string? reason)
    {
        var properties = new Dictionary<string, string>
        {
            ["count"] = count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["revoked"] = count > 0 ? "true" : "false"
        };

        if (reason != null)
        {
            properties["reason"] = reason;
        }

        return properties;
    }

    private async Task<Result<IUser>> ValidateUserTenantAsync(
        Guid userId,
        TenantContext tenant,
        AuditContext? audit,
        string eventType,
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

        return result;
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
}

/// <summary>
/// Optional dependencies used by recovery-code service operations.
/// </summary>
/// <param name="options">Recovery-code options.</param>
/// <param name="timeProvider">Clock used for recovery-code timestamps.</param>
/// <param name="securityEventSink">Receives recovery-code security events.</param>
/// <param name="notificationService">Sends recovery-code security notifications.</param>
public sealed class RecoveryCodeServiceDependencies(
    IOptions<RecoveryCodeOptions> options,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null,
    ISecurityNotificationService? notificationService = null)
{
    /// <summary>
    /// Gets the configured recovery-code options.
    /// </summary>
    public IOptions<RecoveryCodeOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Gets the clock used for recovery-code timestamps.
    /// </summary>
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Gets the sink used to record recovery-code security events.
    /// </summary>
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;

    /// <summary>
    /// Gets the service used to send recovery-code security notifications.
    /// </summary>
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
