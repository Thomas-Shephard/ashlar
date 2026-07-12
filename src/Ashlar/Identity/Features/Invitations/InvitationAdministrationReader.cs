namespace Ashlar.Identity.Features.Invitations;

internal sealed class InvitationAdministrationReader(IInvitationRepository repository, TimeProvider? timeProvider = null)
    : IInvitationAdministrationReader
{
    private readonly IInvitationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<Result<InvitationSearchResult>> SearchInvitationsAsync(SearchInvitationsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!InvitationAdministrationService.TryValidateSearchRequest(request, out var failure)) return failure;

        var limit = Math.Min(request.Limit, InvitationAdministrationService.MaximumLimit);
        var invitations = await _repository.SearchInvitationsAsync(request with { Limit = limit + 1 }, _timeProvider.GetUtcNow(), cancellationToken);
        return Result.Success(new InvitationSearchResult(invitations.Take(limit).ToList().AsReadOnly(), limit, request.Offset, invitations.Count > limit));
    }

    public async Task<Result<InvitationAdministrationSummary>> GetInvitationAsync(InvitationAdministrationLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!InvitationAdministrationService.TryValidateLookupRequest(request, out var failure)) return failure;

        var invitation = await _repository.GetInvitationAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        return invitation == null || (!request.IncludeAllTenants && !AdministrationScopeValidation.IncludesTenant(request.Tenant!, invitation.TenantId))
            ? Result.Failure<InvitationAdministrationSummary>(AshlarFailureCodes.InvitationNotFound, "Invitation was not found.")
            : Result.Success(invitation);
    }
}
