using Ashlar.Auditing;

namespace Ashlar.Identity.Features.AccountLockout;

internal sealed class AccountLockoutAdministrationService(
    IAccountLockoutRepository repository,
    AccountLockoutAdministrationServiceDependencies? dependencies = null) : IAccountLockoutAdministrationService
{
    internal const int MaximumLimit = 100;
    internal const int MaximumReasonLength = 512;

    private readonly IAccountLockoutRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = dependencies?.TimeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(dependencies?.SecurityEventSink, dependencies?.TimeProvider ?? TimeProvider.System);
    private readonly IAshlarTransactionProvider? _transactionProvider = dependencies?.TransactionProvider;

    public async Task<Result<AccountLockoutSearchResult>> SearchLockoutsAsync(SearchAccountLockoutsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Offset < 0)
        {
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        }

        if (request.Limit < 1)
        {
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        }

        if (request is { Tenant: null, IncludeAllTenants: false })
        {
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError, "Tenant scope must be explicit.");
        }

        if (request is { Tenant: not null, IncludeAllTenants: true })
        {
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError, "Tenant scope cannot be combined with all-tenant search.");
        }

        if (request.UserId == Guid.Empty)
        {
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError, "User ID cannot be empty.");
        }

        if (request.Provider is { IsConfigured: false })
        {
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError, "Provider key must be fully initialized with a configured provider type and name.");
        }

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Limit = limit + 1 };
        var now = _timeProvider.GetUtcNow();
        var records = await _repository.SearchAsync(repositoryRequest, now, cancellationToken);
        var items = records
            .Select(record => ToSummary(record, now))
            .ToList();
        var hasMore = items.Count > limit;
        var page = items.Take(limit).ToList().AsReadOnly();

        return Result.Success(new AccountLockoutSearchResult(page, limit, request.Offset, hasMore));
    }

    public async Task<Result<AccountLockoutStatus>> GetLockoutStatusAsync(
        Guid userId,
        AuthenticationProviderKey provider,
        AccountLockoutStatusRequest request,
        CancellationToken cancellationToken = default)
    {
        if (ValidateScopedOperation(userId, provider, request, out var tenantId) is { } failure)
        {
            return Result.Failure<AccountLockoutStatus>(failure);
        }

        var record = await _repository.GetAsync(userId, tenantId, provider, cancellationToken);
        return Result.Success(ToStatus(userId, tenantId, provider, record, _timeProvider.GetUtcNow()));
    }

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

        await using var transaction = _transactionProvider == null
            ? null
            : await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var reset = await _repository.ResetAsync(userId, tenantId, provider, cancellationToken);
        await RecordResetAsync(userId, tenantId, provider, reset, request, cancellationToken);
        if (transaction != null)
        {
            await transaction.CommitAsync(cancellationToken);
        }

        var status = reset ? AccountLockoutResetStatus.Reset : AccountLockoutResetStatus.NotFound;
        return Result.Success(new ResetAccountLockoutResult(status, userId, tenantId, provider));
    }

    private static AccountLockoutAdministrationSummary ToSummary(AccountLockoutRecord record, DateTimeOffset now)
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

    private static AccountLockoutStatus ToStatus(
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

    private static AshlarFailure? ValidateScopedOperation(
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
    ISecurityEventSink? SecurityEventSink = null,
    IAshlarTransactionProvider? TransactionProvider = null);
