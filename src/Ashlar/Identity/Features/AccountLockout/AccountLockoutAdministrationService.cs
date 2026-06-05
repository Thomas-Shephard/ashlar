using Ashlar.Auditing;

namespace Ashlar.Identity.Features.AccountLockout;

/// <summary>
/// Implements administrator-oriented automatic account lockout visibility and reset operations.
/// </summary>
/// <param name="repository">The durable lockout repository.</param>
/// <param name="dependencies">The optional operational dependencies.</param>
public sealed class AccountLockoutAdministrationService(
    IAccountLockoutRepository repository,
    AccountLockoutAdministrationServiceDependencies? dependencies = null) : IAccountLockoutAdministrationService
{
    internal const int MaximumLimit = 100;
    internal const int MaximumReasonLength = 512;

    private readonly IAccountLockoutRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = dependencies?.TimeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(dependencies?.SecurityEventSink, dependencies?.TimeProvider ?? TimeProvider.System);

    /// <inheritdoc />
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

        if (request.Provider is { } provider && IsInvalidProvider(provider))
        {
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError, "Provider key must be fully initialized.");
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

    /// <inheritdoc />
    public async Task<Result<AccountLockoutStatus>> GetLockoutStatusAsync(
        Guid userId,
        AuthenticationProviderKey provider,
        AccountLockoutAdministrationRequest request,
        CancellationToken cancellationToken = default)
    {
        if (ValidateScopedOperation(userId, provider, request, out var tenantId) is { } failure)
        {
            return Result.Failure<AccountLockoutStatus>(failure);
        }

        var record = await _repository.GetAsync(userId, tenantId, provider, cancellationToken);
        return Result.Success(ToStatus(userId, tenantId, provider, record, _timeProvider.GetUtcNow()));
    }

    /// <inheritdoc />
    public async Task<Result<bool>> ResetLockoutAsync(
        Guid userId,
        AuthenticationProviderKey provider,
        ResetAccountLockoutRequest request,
        CancellationToken cancellationToken = default)
    {
        if (ValidateScopedOperation(userId, provider, request, out var tenantId) is { } failure)
        {
            return Result.Failure<bool>(failure);
        }

        if (ValidateReason(request.Reason) is { } reasonFailure)
        {
            return Result.Failure<bool>(reasonFailure);
        }

        var reset = await _repository.ResetAsync(userId, tenantId, provider, cancellationToken);
        await RecordResetAsync(userId, tenantId, provider, reset, request, cancellationToken);
        return Result.Success(reset);
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

    private static bool IsInvalidProvider(AuthenticationProviderKey provider)
    {
        return provider.Type == default || string.IsNullOrWhiteSpace(provider.Name);
    }

    private static AshlarFailure? ValidateScopedOperation(
        Guid userId,
        AuthenticationProviderKey provider,
        AccountLockoutAdministrationRequest request,
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

        if (IsInvalidProvider(provider))
        {
            return new AshlarFailure(AshlarFailureCodes.ValidationError, "Provider key must be fully initialized.");
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

/// <summary>
/// Optional dependencies for <see cref="AccountLockoutAdministrationService" />.
/// </summary>
/// <param name="TimeProvider">The optional clock.</param>
/// <param name="SecurityEventSink">The optional security event sink.</param>
public sealed record AccountLockoutAdministrationServiceDependencies(
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null);
