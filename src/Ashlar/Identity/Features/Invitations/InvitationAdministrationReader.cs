using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Invitations;

internal sealed class InvitationAdministrationReader(IInvitationRepository repository, IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer, IPersistentSecurityEventSink auditSink, TimeProvider? timeProvider = null)
    : IInvitationAdministrationReader
{
    private readonly IInvitationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly AccountSecurityOperationBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

    public async Task<Result<InvitationSearchResult>> SearchInvitationsAsync(AccountSecurityActorContext actor, SearchInvitationsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!InvitationAdministrationService.TryValidateSearchRequest(request, out var failure)) return failure;
        if (await _boundary.AuthorizeAsync(actor, request.Tenant, request.IncludeAllTenants, Guid.Empty,
                AccountSecurityOperation.SearchInvitations, cancellationToken) is { } authorizationFailure)
            return Result.Failure<InvitationSearchResult>(authorizationFailure);

        var limit = Math.Min(request.Limit, InvitationAdministrationService.MaximumLimit);
        List<InvitationAdministrationSummary> invitations;
        try
        {
            invitations = (await _repository.SearchInvitationsAsync(request with { Limit = limit + 1 }, _timeProvider.GetUtcNow(), cancellationToken)
                ?? throw new InvalidOperationException("The invitation administration provider returned a null result.")).ToList();
        }
        catch
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchInvitations);
            throw;
        }
        if (invitations.Any(invitation => invitation is null || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, invitation.TenantId)
            || request.Email != null && !string.Equals(invitation.DisplayEmail, request.Email, StringComparison.OrdinalIgnoreCase)
            || request.EmailQuery != null && (invitation.DisplayEmail is null
                || !invitation.DisplayEmail.Contains(request.EmailQuery, StringComparison.OrdinalIgnoreCase))))
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchInvitations);
            throw new InvalidOperationException("The invitation administration provider returned a result outside the authorized scope.");
        }
        await _boundary.RecordSuccessAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchInvitations);
        return Result.Success(new InvitationSearchResult(invitations.Take(limit).ToList().AsReadOnly(), limit, request.Offset, invitations.Count > limit));
    }

    public async Task<Result<InvitationAdministrationSummary>> GetInvitationAsync(AccountSecurityActorContext actor, InvitationAdministrationLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!InvitationAdministrationService.TryValidateLookupRequest(request, out var failure)) return failure;
        if (await _boundary.AuthorizeAsync(actor, request.Tenant, request.IncludeAllTenants, Guid.Empty,
                AccountSecurityOperation.ReadInvitation, cancellationToken) is { } authorizationFailure)
            return Result.Failure<InvitationAdministrationSummary>(authorizationFailure);

        InvitationAdministrationSummary? invitation;
        try
        {
            invitation = await _repository.GetInvitationAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        }
        catch
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadInvitation);
            throw;
        }
        if (invitation == null || invitation.Id != request.InvitationId || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, invitation.TenantId))
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadInvitation);
            return Result.Failure<InvitationAdministrationSummary>(AshlarFailureCodes.InvitationNotFound, "Invitation was not found.");
        }
        await _boundary.RecordSuccessAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadInvitation);
        return Result.Success(invitation);
    }
}
