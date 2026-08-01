using Ashlar.Auditing;

namespace Ashlar.Identity.Features.AccountLockout;

internal sealed class AccountLockoutAdministrationReader(IAccountLockoutRepository repository, IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer, IPersistentSecurityEventSink auditSink, TimeProvider? timeProvider = null)
    : IAccountLockoutAdministrationReader
{
    private readonly IAccountLockoutRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly AccountSecurityOperationBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

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
        if (await _boundary.AuthorizeAsync(actor, request.Tenant, request.IncludeAllTenants, request.UserId ?? Guid.Empty,
                AccountSecurityOperation.SearchAccountLockouts, cancellationToken, request.Provider) is { } authorizationFailure)
            return Result.Failure<AccountLockoutSearchResult>(authorizationFailure);

        var limit = Math.Min(request.Limit, AccountLockoutAdministrationService.MaximumLimit);
        var now = _timeProvider.GetUtcNow();
        List<AccountLockoutRecord> records;
        try
        {
            records = (await _repository.SearchAsync(request with { Limit = limit + 1 }, now, cancellationToken)
                ?? throw new InvalidOperationException("The account-lockout administration provider returned a null result.")).ToList();
        }
        catch
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAccountLockouts);
            throw;
        }
        if (records.Any(record => record is null || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants,
                record.TenantId, request.UserId, record.UserId) || request.Provider is { } provider && record.Provider != provider))
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAccountLockouts);
            throw new InvalidOperationException("The account-lockout administration provider returned a result outside the authorized scope.");
        }
        await _boundary.RecordSuccessAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAccountLockouts);
        var items = records.Select(record => AccountLockoutAdministrationService.ToSummary(record, now)).ToList();
        return Result.Success(new AccountLockoutSearchResult(items.Take(limit).ToList().AsReadOnly(), limit, request.Offset, items.Count > limit));
    }

    public async Task<Result<AccountLockoutStatus>> GetLockoutStatusAsync(AccountSecurityActorContext actor, AccountLockoutStatusRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (AccountLockoutAdministrationService.ValidateScopedOperation(request, out var tenantId) is { } failure)
            return Result.Failure<AccountLockoutStatus>(failure);
        if (await _boundary.AuthorizeAsync(actor, request.Tenant, false, request.UserId,
                AccountSecurityOperation.ReadAccountLockout, cancellationToken, request.Provider) is { } authorizationFailure)
            return Result.Failure<AccountLockoutStatus>(authorizationFailure);

        AccountLockoutRecord? record;
        try
        {
            record = await _repository.GetAsync(request.UserId, tenantId, request.Provider, cancellationToken);
        }
        catch
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, false, AccountSecurityOperation.ReadAccountLockout);
            throw;
        }
        if (record is not null && (record.UserId != request.UserId || record.TenantId != tenantId || record.Provider != request.Provider))
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, false, AccountSecurityOperation.ReadAccountLockout);
            return Result.Failure<AccountLockoutStatus>(AshlarFailureCodes.ValidationError);
        }
        await _boundary.RecordSuccessAsync(actor, request.Tenant, false, AccountSecurityOperation.ReadAccountLockout);
        return Result.Success(AccountLockoutAdministrationService.ToStatus(request.UserId, tenantId, request.Provider, record, _timeProvider.GetUtcNow()));
    }
}
