using Ashlar.Auditing;

namespace Ashlar.Identity.Features.AccountLockout;

internal sealed class AccountLockoutAdministrationService(
    IAccountLockoutRepository repository,
    AccountLockoutAdministrationServiceDependencies dependencies) : IAccountLockoutAdministrationService
{
    internal const int MaximumLimit = 100;
    internal const int MaximumReasonLength = 512;

    private readonly IAccountLockoutRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly AccountLockoutAdministrationServiceDependencies _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly TimeProvider _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
    private readonly IAshlarDurableTransactionProvider _transactionProvider = dependencies.TransactionProvider ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly SecurityEventEmitter _securityEvents = new(DurableSecurityMutationComposition.Require(dependencies.SecurityEventSink, dependencies.TransactionProvider, "Account-lockout reset"), dependencies.TimeProvider ?? TimeProvider.System);

    public async Task<Result<ResetAccountLockoutResult>> ResetLockoutAsync(
        Guid userId,
        AuthenticationProviderKey provider,
        ResetAccountLockoutRequest request,
        CancellationToken cancellationToken = default)
    {
        if (ValidateScopedOperation(userId, provider, request, out var tenantId) is { } failure)
        {
            return Result.Failure<ResetAccountLockoutResult>(failure);
        }

        if (ValidateReason(request.Reason) is { } reasonFailure)
        {
            return Result.Failure<ResetAccountLockoutResult>(reasonFailure);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var reset = await _repository.ResetAsync(userId, tenantId, provider, cancellationToken);
        await RecordResetAsync(userId, tenantId, provider, reset, request, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        var status = reset ? AccountLockoutResetStatus.Reset : AccountLockoutResetStatus.NotFound;
        return Result.Success(new ResetAccountLockoutResult(status, userId, tenantId, provider));
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
        Guid userId,
        AuthenticationProviderKey provider,
        AccountLockoutStatusRequest request,
        out Guid? tenantId)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ValidateScopedOperation(userId, provider, request.Tenant, out tenantId);
    }

    private static AshlarFailure? ValidateScopedOperation(
        Guid userId,
        AuthenticationProviderKey provider,
        ResetAccountLockoutRequest request,
        out Guid? tenantId)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ValidateScopedOperation(userId, provider, request.Tenant, out tenantId);
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
            Audit = request.Audit,
            Provider = provider,
            Properties = properties
        }, cancellationToken);
    }
}

internal sealed record AccountLockoutAdministrationServiceDependencies(
    TimeProvider? TimeProvider = null,
    SecurityEventFanOutSink? SecurityEventSink = null,
    IAshlarDurableTransactionProvider? TransactionProvider = null);
