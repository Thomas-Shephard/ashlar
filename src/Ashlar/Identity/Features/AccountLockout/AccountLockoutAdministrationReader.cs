using Ashlar.Auditing;

namespace Ashlar.Identity.Features.AccountLockout;

internal sealed class AccountLockoutAdministrationReader(IAccountLockoutRepository repository, IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer, IPersistentSecurityEventSink auditSink, TimeProvider? timeProvider = null)
    : IAccountLockoutAdministrationReader
{
    private readonly IAccountLockoutRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly AdminReadBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

    public async Task<Result<AccountLockoutSearchResult>> SearchLockoutsAsync(AccountSecurityActorContext actor, SearchAccountLockoutsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Offset < 0 || request.Limit < 1 || request.UserId == Guid.Empty
            || request is { Tenant: null, IncludeAllTenants: false }
            || request is { Tenant: not null, IncludeAllTenants: true }
            || request.Provider is { IsConfigured: false })
        {
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError);
        }
        if (!await _boundary.AuthorizeAsync(actor, request.Tenant, request.IncludeAllTenants, request.UserId ?? Guid.Empty,
                AccountSecurityOperation.SearchAccountLockouts, cancellationToken, recordSuccess: false,
                provider: request.Provider)) return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError);

        var limit = Math.Min(request.Limit, AccountLockoutAdministrationService.MaximumLimit);
        var now = _timeProvider.GetUtcNow();
        var records = await _repository.SearchAsync(request with { Limit = limit + 1 }, now, cancellationToken);
        if (records.Any(record => !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants,
                record.TenantId, request.UserId, record.UserId) || request.Provider is { } provider && record.Provider != provider))
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAccountLockouts);
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError);
        }
        await _boundary.RecordSuccessAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAccountLockouts);
        var items = records.Select(record => AccountLockoutAdministrationService.ToSummary(record, now)).ToList();
        return Result.Success(new AccountLockoutSearchResult(items.Take(limit).ToList().AsReadOnly(), limit, request.Offset, items.Count > limit));
    }

    public async Task<Result<AccountLockoutStatus>> GetLockoutStatusAsync(AccountSecurityActorContext actor, Guid userId, AuthenticationProviderKey provider, AccountLockoutStatusRequest request, CancellationToken cancellationToken = default)
    {
        if (AccountLockoutAdministrationService.ValidateScopedOperation(userId, provider, request, out var tenantId) is { } failure)
            return Result.Failure<AccountLockoutStatus>(failure);
        if (!await _boundary.AuthorizeAsync(actor, request.Tenant, false, userId,
                AccountSecurityOperation.ReadAccountLockout, cancellationToken, recordSuccess: false,
                provider: provider)) return Result.Failure<AccountLockoutStatus>(AshlarFailureCodes.ValidationError);

        var record = await _repository.GetAsync(userId, tenantId, provider, cancellationToken);
        if (record is not null && (record.UserId != userId || record.TenantId != tenantId || record.Provider != provider))
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, false, AccountSecurityOperation.ReadAccountLockout);
            return Result.Failure<AccountLockoutStatus>(AshlarFailureCodes.ValidationError);
        }
        await _boundary.RecordSuccessAsync(actor, request.Tenant, false, AccountSecurityOperation.ReadAccountLockout);
        return Result.Success(AccountLockoutAdministrationService.ToStatus(userId, tenantId, provider, record, _timeProvider.GetUtcNow()));
    }
}
