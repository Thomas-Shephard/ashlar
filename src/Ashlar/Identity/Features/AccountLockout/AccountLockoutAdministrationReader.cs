namespace Ashlar.Identity.Features.AccountLockout;

internal sealed class AccountLockoutAdministrationReader(IAccountLockoutRepository repository, TimeProvider? timeProvider = null)
    : IAccountLockoutAdministrationReader
{
    private readonly IAccountLockoutRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<Result<AccountLockoutSearchResult>> SearchLockoutsAsync(SearchAccountLockoutsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Offset < 0 || request.Limit < 1 || request.UserId == Guid.Empty
            || request is { Tenant: null, IncludeAllTenants: false }
            || request is { Tenant: not null, IncludeAllTenants: true }
            || request.Provider is { IsConfigured: false })
        {
            return Result.Failure<AccountLockoutSearchResult>(AshlarFailureCodes.ValidationError);
        }

        var limit = Math.Min(request.Limit, AccountLockoutAdministrationService.MaximumLimit);
        var now = _timeProvider.GetUtcNow();
        var records = await _repository.SearchAsync(request with { Limit = limit + 1 }, now, cancellationToken);
        var items = records.Select(record => AccountLockoutAdministrationService.ToSummary(record, now)).ToList();
        return Result.Success(new AccountLockoutSearchResult(items.Take(limit).ToList().AsReadOnly(), limit, request.Offset, items.Count > limit));
    }

    public async Task<Result<AccountLockoutStatus>> GetLockoutStatusAsync(Guid userId, AuthenticationProviderKey provider, AccountLockoutStatusRequest request, CancellationToken cancellationToken = default)
    {
        if (AccountLockoutAdministrationService.ValidateScopedOperation(userId, provider, request, out var tenantId) is { } failure)
            return Result.Failure<AccountLockoutStatus>(failure);

        var record = await _repository.GetAsync(userId, tenantId, provider, cancellationToken);
        return Result.Success(AccountLockoutAdministrationService.ToStatus(userId, tenantId, provider, record, _timeProvider.GetUtcNow()));
    }
}
