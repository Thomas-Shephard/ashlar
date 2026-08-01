using Ashlar.Auditing;

namespace Ashlar.Identity.Features.AccountLockout;

internal sealed class AccountLockoutAdministrationService : IAccountLockoutAdministrationService
{
    internal const int MaximumLimit = 100;
    internal const int MaximumReasonLength = 512;

    private readonly IAccountLockoutRepository _repository;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly AshlarDurableTransactionProvider _transactionProvider;
    private readonly AccountSecurityOperationBoundary _boundary;

    public AccountLockoutAdministrationService(
        IAccountLockoutRepository repository,
        AccountLockoutAdministrationServiceDependencies dependencies,
        IAuthenticationSessionRepository sessions,
        IAccountSecurityOperationAuthorizer authorizer,
        IPersistentSecurityEventSink auditSink)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        ArgumentNullException.ThrowIfNull(dependencies);
        _transactionProvider = dependencies.TransactionProvider ?? throw new ArgumentNullException(nameof(dependencies));
        _securityEvents = new SecurityEventEmitter(
            DurableSecurityMutationComposition.Require(dependencies.SecurityEventSink, _transactionProvider, "Account-lockout reset", repository),
            dependencies.TimeProvider ?? TimeProvider.System);
        _boundary = new(sessions, authorizer, auditSink, dependencies.TimeProvider ?? TimeProvider.System,
            IAccountSecurityAdministrationService.ProofPurpose, AshlarSecurityEventTypes.AccountLockoutReset);
    }

    public async Task<Result<ResetAccountLockoutResult>> ResetLockoutAsync(
        AccountSecurityActorContext actor,
        ResetAccountLockoutRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (ValidateScopedOperation(request, out var tenantId) is { } failure)
        {
            return Result.Failure<ResetAccountLockoutResult>(failure);
        }

        if (ValidateReason(request.Reason) is { } reasonFailure)
        {
            return Result.Failure<ResetAccountLockoutResult>(reasonFailure);
        }
        if (await _boundary.AuthorizeAsync(actor, request.Tenant, false, request.UserId,
                AccountSecurityOperation.ResetAccountLockout, cancellationToken, request.Provider) is { } authorizationFailure)
            return Result.Failure<ResetAccountLockoutResult>(authorizationFailure);

        var existing = await _repository.GetAsync(request.UserId, tenantId, request.Provider, cancellationToken);
        if (existing is not null && (existing.UserId != request.UserId || existing.TenantId != tenantId || existing.Provider != request.Provider))
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, false, AccountSecurityOperation.ResetAccountLockout);
            return Result.Failure<ResetAccountLockoutResult>(AshlarFailureCodes.ValidationError);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var reset = existing is not null && await _repository.ResetAsync(request.UserId, tenantId, request.Provider, cancellationToken);
        await RecordResetAsync(request.UserId, tenantId, request.Provider, reset, request, actor.Audit, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        var status = reset ? AccountLockoutResetStatus.Reset : AccountLockoutResetStatus.NotFound;
        return Result.Success(new ResetAccountLockoutResult(status, request.UserId, tenantId, request.Provider));
    }

    internal static AccountLockoutAdministrationSummary ToSummary(AccountLockoutRecord record, DateTimeOffset now)
    {
        return new AccountLockoutAdministrationSummary(
            record.UserId,
            record.TenantId,
            record.Provider,
            record.FailedAttemptCount,
            record.FirstFailedAt,
            record.LastFailedAt,
            record.LockedUntil,
            IsLocked(record, now));
    }

    internal static AccountLockoutStatus ToStatus(
        Guid userId,
        Guid? tenantId,
        AuthenticationProviderKey provider,
        AccountLockoutRecord? record,
        DateTimeOffset now)
    {
        return record == null
            ? AccountLockoutStatus.None(userId, tenantId, provider)
            : new AccountLockoutStatus(
                userId,
                tenantId,
                provider,
                record.FailedAttemptCount,
                record.FirstFailedAt,
                record.LastFailedAt,
                record.LockedUntil,
                IsLocked(record, now));
    }

    private static bool IsLocked(AccountLockoutRecord record, DateTimeOffset now)
    {
        return record.LockedUntil is { } lockedUntil && lockedUntil > now;
    }

    internal static AshlarFailure? ValidateScopedOperation(
        AccountLockoutStatusRequest request,
        out Guid? tenantId)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ValidateScopedOperation(request.UserId, request.Provider, request.Tenant, out tenantId);
    }

    private static AshlarFailure? ValidateScopedOperation(
        ResetAccountLockoutRequest request,
        out Guid? tenantId)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ValidateScopedOperation(request.UserId, request.Provider, request.Tenant, out tenantId);
    }

    private static AshlarFailure? ValidateScopedOperation(
        Guid userId,
        AuthenticationProviderKey provider,
        TenantContext? tenant,
        out Guid? tenantId)
    {
        tenantId = null;

        if (userId == Guid.Empty)
        {
            return new AshlarFailure(AshlarFailureCodes.ValidationError, "User ID cannot be empty.");
        }

        if (!provider.IsConfigured)
        {
            return new AshlarFailure(AshlarFailureCodes.ValidationError, "Provider key must be fully initialized with a configured provider type and name.");
        }

        if (tenant == null)
        {
            return new AshlarFailure(AshlarFailureCodes.ValidationError, "Tenant scope must be explicit.");
        }

        tenantId = tenant.TenantId;
        return null;
    }

    private static AshlarFailure? ValidateReason(string? reason)
    {
        return reason?.Length > MaximumReasonLength
            ? new AshlarFailure(AshlarFailureCodes.ValidationError, $"Reason cannot exceed {MaximumReasonLength} characters.")
            : null;
    }

    private Task RecordResetAsync(
        Guid userId,
        Guid? tenantId,
        AuthenticationProviderKey provider,
        bool lockoutStateCleared,
        ResetAccountLockoutRequest request,
        AuditContext audit,
        CancellationToken cancellationToken)
    {
        var properties = new Dictionary<string, string>
        {
            ["lockout_state_cleared"] = lockoutStateCleared ? "true" : "false",
            ["tenant_scope"] = tenantId.HasValue ? "tenant" : "global"
        };

        if (tenantId.HasValue)
        {
            properties["tenant_id"] = tenantId.Value.ToString();
        }

        if (request.Reason != null)
        {
            properties["reason"] = request.Reason;
        }

        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AccountLockoutReset,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = tenantId,
            Audit = audit,
            Provider = provider,
            Properties = properties
        }, cancellationToken);
    }
}

internal sealed record AccountLockoutAdministrationServiceDependencies(
    TimeProvider? TimeProvider = null,
    SecurityEventFanOutSink? SecurityEventSink = null,
    AshlarDurableTransactionProvider? TransactionProvider = null);
