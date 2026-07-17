using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.RecoveryCode;

internal sealed class RecoveryCodeService : IRecoveryCodeService, IRecoveryCodeMutationExecutor
{
    internal const string ProofPurpose = "recovery-code-management";
    private const string EmptyUserIdMessage = "User ID cannot be empty.";

    private readonly IUserRepository _userRepository;
    private readonly ICredentialRepository _credentialRepository;
    private readonly AshlarDurableTransactionProvider _transactionProvider;
    private readonly Security.Hashing.PasswordHasherSelector _hasherSelector;
    private readonly RecoveryCodeOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly SecurityNotificationEmitter _notifications;
    private readonly IAccountSecurityOperationAuthorizer _authorizer;
    private readonly ActiveSessionFreshProofValidator _proofValidator;

    public RecoveryCodeService(
        IUserRepository userRepository,
        ICredentialRepository credentialRepository,
        AshlarDurableTransactionProvider transactionProvider,
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
        _proofValidator = dependencies.ProofValidator;
        _options = dependencies.Options.Value;
        _timeProvider = dependencies.TimeProvider;
        _securityEvents = new SecurityEventEmitter(DurableSecurityMutationComposition.Require(dependencies.SecurityEventSink, transactionProvider, "Recovery-code mutations", userRepository, credentialRepository), _timeProvider);
        _notifications = new SecurityNotificationEmitter(dependencies.NotificationService);
        _authorizer = dependencies.Authorizer;
    }

    public async Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesAsync(RecoveryCodeGenerationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var failure = await ValidatePublicActorAsync(request, AshlarSecurityEventTypes.RecoveryCodesGenerated, cancellationToken);
        if (failure != null) return Result.Failure<IReadOnlyList<string>>(failure.Value);
        if (request.CodeCount is <= 0 || request.CodeCount > _options.CodeCount * 2)
        {
            await RecordPublicFailureAsync(request, AshlarSecurityEventTypes.RecoveryCodesGenerated,
                AshlarFailureCodes.InvalidCodeCount, request.Audit, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidCodeCount);
        }
        if (request.ExpiresAfter is { } expiresAfter && expiresAfter <= TimeSpan.Zero)
        {
            await RecordPublicFailureAsync(request, AshlarSecurityEventTypes.RecoveryCodesGenerated,
                AshlarFailureCodes.InvalidExpiry, request.Audit, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidExpiry);
        }
        failure = await AuthorizePublicRequestAsync(request, AccountSecurityOperation.GenerateRecoveryCodes,
            AshlarSecurityEventTypes.RecoveryCodesGenerated, cancellationToken);
        if (failure != null) return Result.Failure<IReadOnlyList<string>>(failure.Value);

        return await GenerateRecoveryCodesCoreAsync(request.TargetUserId, new RecoveryCodeGenerationExecutionRequest(
            request.Audit, request.Tenant, request.IncludeAllTenants, request.Reason, request.ReplaceExisting,
            request.CodeCount, request.ExpiresAfter), cancellationToken);
    }

    Task<Result<IReadOnlyList<string>>> IRecoveryCodeMutationExecutor.GenerateRecoveryCodesAsync(
        Guid userId, RecoveryCodeGenerationExecutionRequest request, CancellationToken cancellationToken) =>
        GenerateRecoveryCodesCoreAsync(userId, request, cancellationToken);

    private async Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesCoreAsync(Guid userId, RecoveryCodeGenerationExecutionRequest request, CancellationToken cancellationToken)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException(EmptyUserIdMessage, nameof(userId));
        }

        var userResult = await ValidateUserScopeAsync(userId, request.Tenant, request.IncludeAllTenants, request.Audit,
            AshlarSecurityEventTypes.RecoveryCodesGenerated, cancellationToken);
        if (!userResult.TryGetValue(out var user))
        {
            return Result.Failure<IReadOnlyList<string>>(userResult.GetFailureOr(AshlarFailureCodes.UserNotFoundOrUnavailable));
        }

        var codeCount = request.CodeCount ?? _options.CodeCount;
        if (codeCount <= 0 || codeCount > _options.CodeCount * 2)
        {
            await RecordGenerationFailureAsync(userId, GetAuditTenantId(request.Tenant, request.IncludeAllTenants, user), request.Audit, AshlarFailureCodes.InvalidCodeCount, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidCodeCount);
        }

        if (_options.CodeLength <= 0 || _options.GroupSize <= 0)
        {
            await RecordGenerationFailureAsync(userId, GetAuditTenantId(request.Tenant, request.IncludeAllTenants, user), request.Audit, AshlarFailureCodes.InvalidConfiguration, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidConfiguration);
        }

        var expiresAfter = request.ExpiresAfter ?? _options.ExpiresAfter;
        if (expiresAfter.HasValue && expiresAfter.Value <= TimeSpan.Zero)
        {
            await RecordGenerationFailureAsync(userId, GetAuditTenantId(request.Tenant, request.IncludeAllTenants, user), request.Audit, AshlarFailureCodes.InvalidExpiry, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidExpiry);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        await _credentialRepository.AcquireUserMutationLockAsync(userId, cancellationToken);
        var lockedUserResult = await ValidateUserScopeAsync(userId, request.Tenant, request.IncludeAllTenants, request.Audit,
            AshlarSecurityEventTypes.RecoveryCodesGenerated, cancellationToken);
        if (!lockedUserResult.TryGetValue(out user))
        {
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(lockedUserResult.GetFailureOr(AshlarFailureCodes.UserNotFoundOrUnavailable));
        }

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

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = GetAuditTenantId(request.Tenant, request.IncludeAllTenants, user),
            Audit = request.Audit,
            Provider = _options.ProviderKey,
            Properties = new Dictionary<string, string>
            {
                ["count"] = codeCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
            }
        }, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _notifications.NotifyAsync(SecurityNotificationType.RecoveryCodesGenerated, user, now, context: ToNotificationContext(request.Audit), metadata: new Dictionary<string, string>
            {
                ["count"] = codeCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
            }, cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success<IReadOnlyList<string>>(rawCodes);
    }

    public async Task<Result<int>> RevokeRecoveryCodesAsync(RevokeRecoveryCodesRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var failure = await ValidatePublicRequestAsync(request, AccountSecurityOperation.RevokeRecoveryCodes,
            AshlarSecurityEventTypes.RecoveryCodesRevoked, cancellationToken);
        if (failure != null) return Result.Failure<int>(failure.Value);

        return await RevokeRecoveryCodesCoreAsync(request.TargetUserId, new RevokeRecoveryCodesExecutionRequest(
            request.Audit, request.Tenant, request.IncludeAllTenants, request.Reason), cancellationToken);
    }

    Task<Result<int>> IRecoveryCodeMutationExecutor.RevokeRecoveryCodesAsync(
        Guid userId, RevokeRecoveryCodesExecutionRequest request, CancellationToken cancellationToken) =>
        RevokeRecoveryCodesCoreAsync(userId, request, cancellationToken);

    private async Task<Result<int>> RevokeRecoveryCodesCoreAsync(Guid userId, RevokeRecoveryCodesExecutionRequest request, CancellationToken cancellationToken)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException(EmptyUserIdMessage, nameof(userId));
        }
        var userResult = await ValidateUserScopeAsync(userId, request.Tenant, request.IncludeAllTenants, request.Audit,
            AshlarSecurityEventTypes.RecoveryCodesRevoked, cancellationToken);
        if (!userResult.Succeeded)
        {
            return Result.Failure<int>(userResult.GetFailureOr(AshlarFailureCodes.UserNotFoundOrUnavailable));
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        await _credentialRepository.AcquireUserMutationLockAsync(userId, cancellationToken);
        var lockedUserResult = await ValidateUserScopeAsync(userId, request.Tenant, request.IncludeAllTenants, request.Audit,
            AshlarSecurityEventTypes.RecoveryCodesRevoked, cancellationToken);
        if (!lockedUserResult.TryGetValue(out var user))
        {
            await transaction.CommitAsync(cancellationToken);
            return Result.Failure<int>(lockedUserResult.GetFailureOr(AshlarFailureCodes.UserNotFoundOrUnavailable));
        }

        var count = await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RecoveryCodesRevoked,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = GetAuditTenantId(request.Tenant, request.IncludeAllTenants, user),
            Audit = request.Audit,
            Provider = _options.ProviderKey,
            Properties = CreateRevocationProperties(count, request.Reason)
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return Result.Success(count);
    }

    private async Task<AshlarFailureCode?> ValidatePublicRequestAsync(
        AccountSecurityAdministrationRequest request,
        AccountSecurityOperation operation,
        string eventType,
        CancellationToken cancellationToken)
    {
        var failure = await ValidatePublicActorAsync(request, eventType, cancellationToken);
        return failure ?? await AuthorizePublicRequestAsync(request, operation, eventType, cancellationToken);
    }

    private async Task<AshlarFailureCode?> ValidatePublicActorAsync(
        AccountSecurityAdministrationRequest request,
        string eventType,
        CancellationToken cancellationToken)
    {
        if (request.Audit.ActorUserId != request.ActorUserId)
        {
            await RecordPublicFailureAsync(request, eventType, AshlarFailureCodes.ValidationError,
                new AuditContext(request.ActorUserId), cancellationToken);
            return AshlarFailureCodes.ValidationError;
        }

        var failure = await _proofValidator.ValidateAsync(request.ActorUserId, request.ActorTenant,
            request.FreshMfaProof, request.CurrentSessionId, ProofPurpose, cancellationToken);
        if (failure != null)
            await RecordPublicFailureAsync(request, eventType, failure.Value, request.Audit, cancellationToken);
        return failure;
    }

    private async Task<AshlarFailureCode?> AuthorizePublicRequestAsync(
        AccountSecurityAdministrationRequest request,
        AccountSecurityOperation operation,
        string eventType,
        CancellationToken cancellationToken)
    {
        if (await _authorizer.AuthorizeAsync(new AccountSecurityAuthorizationContext(
                request.ActorUserId, request.ActorTenant, request.TargetUserId, request.Tenant,
                request.IncludeAllTenants, operation, CurrentSessionId: request.CurrentSessionId), cancellationToken))
            return null;

        await RecordPublicFailureAsync(request, eventType, AshlarFailureCodes.ValidationError, request.Audit, cancellationToken);
        return AshlarFailureCodes.ValidationError;
    }

    private Task RecordPublicFailureAsync(AccountSecurityAdministrationRequest request, string eventType,
        AshlarFailureCode failure, AuditContext audit, CancellationToken cancellationToken) =>
        _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = request.TargetUserId,
            TenantId = request.Tenant?.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            FailureReason = failure.Value,
            Properties = request.IncludeAllTenants
                ? new Dictionary<string, string> { ["scope"] = "all_tenants" }
                : null
        }, cancellationToken);

    private Task RecordGenerationFailureAsync(
        Guid userId,
        Guid? tenantId,
        AuditContext audit,
        AshlarFailureCode failure,
        CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            FailureReason = failure.Value
        }, cancellationToken);
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

    private async Task<Result<IUser>> ValidateUserScopeAsync(
        Guid userId,
        TenantContext? tenant,
        bool includeAllTenants,
        AuditContext audit,
        string eventType,
        CancellationToken cancellationToken)
    {
        Result<IUser> result;
        if (includeAllTenants)
        {
            var user = await _userRepository.GetUserByIdAsync(userId, cancellationToken);
            result = user == null ? Result.Failure<IUser>(AshlarFailureCodes.UserNotFound) : Result.Success<IUser>(user);
        }
        else
        {
            result = await UserTenantValidator.GetUserInTenantAsync(_userRepository, userId, tenant!, cancellationToken);
        }
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
            TenantId = tenant?.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            FailureReason = failureCode.Value
        }, cancellationToken);

        return result;
    }

    private static Guid? GetAuditTenantId(TenantContext? tenant, bool includeAllTenants, IUser user) =>
        includeAllTenants && user is ITenantUser tenantUser ? tenantUser.TenantId : tenant?.TenantId;

    private static AuthenticationContext ToNotificationContext(AuditContext audit) =>
        new(
            UserId: audit.ActorUserId,
            IpAddress: audit.IpAddress,
            UserAgent: audit.UserAgent,
            CorrelationId: audit.CorrelationId);
}

internal sealed class RecoveryCodeServiceDependencies(
    IOptions<RecoveryCodeOptions> options,
    ActiveSessionFreshProofValidator proofValidator,
    TimeProvider? timeProvider = null,
    SecurityEventFanOutSink? securityEventSink = null,
    ISecurityNotificationService? notificationService = null,
    IAccountSecurityOperationAuthorizer? authorizer = null)
{
    public IOptions<RecoveryCodeOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));
    public ActiveSessionFreshProofValidator ProofValidator { get; } = proofValidator ?? throw new ArgumentNullException(nameof(proofValidator));
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;
    public SecurityEventFanOutSink? SecurityEventSink { get; } = securityEventSink;
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
    public IAccountSecurityOperationAuthorizer Authorizer { get; } = authorizer ?? throw new ArgumentNullException(nameof(authorizer));
}
