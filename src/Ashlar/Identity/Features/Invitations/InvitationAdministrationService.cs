using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Invitations;

/// <summary>
/// Implements administrator invitation search, detail, and revocation operations.
/// </summary>
/// <param name="repository">Repository used for safe administrator invitation lookup and mutation.</param>
/// <param name="dependencies">Optional clock and audit dependencies.</param>
/// <remarks>
/// These operations are intended for administrative diagnostics and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
internal sealed class InvitationAdministrationService(
    IInvitationRepository repository,
    InvitationAdministrationServiceDependencies? dependencies = null) : IInvitationAdministrationService
{
    internal const int MaximumLimit = 100;
    internal const int MaximumReasonLength = 512;

    private readonly IInvitationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = dependencies?.TimeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(dependencies?.SecurityEventSink, dependencies?.TimeProvider ?? TimeProvider.System);

    /// <inheritdoc />
    public async Task<Result<InvitationSearchResult>> SearchInvitationsAsync(SearchInvitationsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateSearchRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Limit = limit + 1 };
        var invitations = await _repository.SearchInvitationsAsync(repositoryRequest, _timeProvider.GetUtcNow(), cancellationToken);
        var hasMore = invitations.Count > limit;
        var page = invitations.Take(limit).ToList().AsReadOnly();

        return Result.Success(new InvitationSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<InvitationAdministrationDetail>> GetInvitationAsync(InvitationAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateDetailRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var invitation = await _repository.GetInvitationAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        return invitation == null || (!request.IncludeAllTenants && !AdministrationScopeValidation.IncludesTenant(request.Tenant!, invitation.TenantId))
            ? Result.Failure<InvitationAdministrationDetail>(AshlarFailureCodes.InvitationNotFound, "Invitation was not found.")
            : Result.Success(invitation);
    }

    /// <inheritdoc />
    public async Task<Result<RevokeInvitationAdministrationResult>> RevokeInvitationAsync(RevokeInvitationAdministrationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateRevokeRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (request.Reason?.Length > MaximumReasonLength)
        {
            return Result.Failure<RevokeInvitationAdministrationResult>(AshlarFailureCodes.ValidationError, $"Reason cannot exceed {MaximumReasonLength} characters.");
        }

        var now = _timeProvider.GetUtcNow();
        var result = await _repository.RevokeInvitationAsync(request, now, cancellationToken);
        if (result == null)
        {
            return Result.Failure<RevokeInvitationAdministrationResult>(AshlarFailureCodes.InvitationNotFound, "Invitation was not found.");
        }

        if (result.Revoked)
        {
            await RecordRevocationAsync(request, result, cancellationToken);
        }

        return Result.Success(result);
    }

    private Task RecordRevocationAsync(
        RevokeInvitationAdministrationRequest request,
        RevokeInvitationAdministrationResult result,
        CancellationToken cancellationToken)
    {
        var requestedTenantId = request.Tenant?.TenantId;
        var invitationTenantId = result.TenantId;
        var tenantScope = "global";
        if (request.IncludeAllTenants)
        {
            tenantScope = "all";
        }
        else if (requestedTenantId.HasValue)
        {
            tenantScope = "tenant";
        }

        var properties = new Dictionary<string, string>
        {
            ["invitation_id"] = result.InvitationId.ToString(),
            ["revoked"] = "true",
            ["status"] = result.Status.ToString(),
            ["tenant_scope"] = tenantScope
        };

        if (invitationTenantId.HasValue)
        {
            properties["tenant_id"] = invitationTenantId.Value.ToString();
        }

        if (request.Reason != null)
        {
            properties["reason"] = request.Reason;
        }

        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.InvitationRevoked,
            Outcome = SecurityEventOutcomes.Success,
            TenantId = invitationTenantId,
            Audit = request.Audit,
            Properties = properties
        }, cancellationToken);
    }

    private static bool TryValidateSearchRequest(SearchInvitationsRequest request, out Result<InvitationSearchResult> failure)
    {
        try
        {
            SearchInvitationsRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<InvitationSearchResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool TryValidateDetailRequest(InvitationAdministrationDetailRequest request, out Result<InvitationAdministrationDetail> failure)
    {
        try
        {
            InvitationAdministrationDetailRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<InvitationAdministrationDetail>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool TryValidateRevokeRequest(RevokeInvitationAdministrationRequest request, out Result<RevokeInvitationAdministrationResult> failure)
    {
        try
        {
            RevokeInvitationAdministrationRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<RevokeInvitationAdministrationResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}

/// <summary>
/// Optional dependencies for <see cref="InvitationAdministrationService" />.
/// </summary>
/// <param name="TimeProvider">Clock used for expiry projection and mutation timestamps.</param>
/// <param name="SecurityEventSink">Security audit event sink used for revocation events.</param>
internal sealed record InvitationAdministrationServiceDependencies(
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null);
