namespace Ashlar.Identity.Features.AccountLockout;

/// <summary>
/// Implements administrator-oriented automatic account lockout visibility and reset operations.
/// </summary>
/// <param name="repository">The durable lockout repository.</param>
/// <param name="timeProvider">The optional clock.</param>
public sealed class AccountLockoutAdministrationService(
    IAccountLockoutRepository repository,
    TimeProvider? timeProvider = null) : IAccountLockoutAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IAccountLockoutRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

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
        AccountLockoutAdministrationRequest request,
        CancellationToken cancellationToken = default)
    {
        if (ValidateScopedOperation(userId, provider, request, out var tenantId) is { } failure)
        {
            return Result.Failure<bool>(failure);
        }

        var reset = await _repository.ResetAsync(userId, tenantId, provider, cancellationToken);
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
        tenantId = null;

        if (userId == Guid.Empty)
        {
            return new AshlarFailure(AshlarFailureCodes.ValidationError, "User ID cannot be empty.");
        }

        if (IsInvalidProvider(provider))
        {
            return new AshlarFailure(AshlarFailureCodes.ValidationError, "Provider key must be fully initialized.");
        }

        if (request.Tenant == null)
        {
            return new AshlarFailure(AshlarFailureCodes.ValidationError, "Tenant scope must be explicit.");
        }

        tenantId = request.Tenant.TenantId;
        return null;
    }
}
