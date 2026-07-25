using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Invitations;

/// <summary>
/// Implements administrator invitation search, single-item lookup, and revocation operations.
/// </summary>
/// <remarks>Every operation requires an active actor session, fresh administration proof, explicit scope, and host authorization.</remarks>
internal sealed class InvitationAdministrationService : IInvitationAdministrationService
{
    internal const int MaximumLimit = 100;
    internal const int MaximumReasonLength = 512;

    private readonly IInvitationRepository _repository;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly AshlarDurableTransactionProvider _transactionProvider;
    private readonly AccountSecurityOperationBoundary _boundary;

    /// <summary>Initializes invitation revocation with durable audit composition.</summary>
    public InvitationAdministrationService(
        IInvitationRepository repository,
        InvitationAdministrationServiceDependencies dependencies,
        IAuthenticationSessionRepository sessions,
        IAccountSecurityOperationAuthorizer authorizer,
        IPersistentSecurityEventSink auditSink)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        ArgumentNullException.ThrowIfNull(dependencies);
        _transactionProvider = dependencies.TransactionProvider ?? throw new ArgumentNullException(nameof(dependencies));
        _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(
            DurableSecurityMutationComposition.Require(dependencies.SecurityEventSink, _transactionProvider, "Invitation revocation", repository),
            _timeProvider);
        _boundary = new(sessions, authorizer, auditSink, _timeProvider,
            IAccountSecurityAdministrationService.ProofPurpose, AshlarSecurityEventTypes.InvitationRevoked);
    }

    /// <inheritdoc />
    public async Task<Result<RevokeInvitationAdministrationResult>> RevokeInvitationAsync(AccountSecurityActorContext actor, RevokeInvitationAdministrationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateRevokeRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (request.Reason?.Length > MaximumReasonLength)
        {
            return Result.Failure<RevokeInvitationAdministrationResult>(AshlarFailureCodes.ValidationError, $"Reason cannot exceed {MaximumReasonLength} characters.");
        }
        if (request.Audit!.ActorUserId != actor.ActorUserId)
        {
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.RevokeInvitation);
            return Result.Failure<RevokeInvitationAdministrationResult>(AshlarFailureCodes.ValidationError);
        }
        if (!await _boundary.AuthorizeAsync(actor, request.Tenant, request.IncludeAllTenants, Guid.Empty,
                AccountSecurityOperation.RevokeInvitation, cancellationToken))
            return Result.Failure<RevokeInvitationAdministrationResult>(AshlarFailureCodes.ValidationError);

        var now = _timeProvider.GetUtcNow();
        RevokeInvitationAdministrationResult? result;
        await using (var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken))
        {
            result = await _repository.RevokeInvitationAsync(request, now, cancellationToken);
            if (result != null && result.InvitationId == request.InvitationId
                && AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, result.TenantId))
            {
                await RecordRevocationAttemptAsync(request, result, cancellationToken);

                await transaction.CommitAsync(cancellationToken);
                return Result.Success(result);
            }
        }

        await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.RevokeInvitation);
        return Result.Failure<RevokeInvitationAdministrationResult>(AshlarFailureCodes.InvitationNotFound, "Invitation was not found.");
    }

    private Task RecordRevocationAttemptAsync(
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
            ["revocation_status"] = result.RevocationStatus.ToString(),
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
            Outcome = result.RevocationStatus == InvitationAdministrationRevocationStatus.Revoked
                ? SecurityEventOutcomes.Success
                : SecurityEventOutcomes.Failure,
            TenantId = invitationTenantId,
            Audit = request.Audit,
            Properties = properties
        }, cancellationToken);
    }

    internal static bool TryValidateSearchRequest(SearchInvitationsRequest request, out Result<InvitationSearchResult> failure)
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

    internal static bool TryValidateLookupRequest(InvitationAdministrationLookupRequest request, out Result<InvitationAdministrationSummary> failure)
    {
        try
        {
            InvitationAdministrationLookupRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<InvitationAdministrationSummary>(AshlarFailureCodes.ValidationError, exception.Message);
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
/// Dependencies for <see cref="InvitationAdministrationService" />.
/// </summary>
/// <param name="TimeProvider">Clock used for expiry projection and mutation timestamps.</param>
/// <param name="SecurityEventSink">Security audit event sink used for revocation events.</param>
/// <param name="TransactionProvider">Transaction provider used to commit invitation revocation with required audit writes.</param>
internal sealed record InvitationAdministrationServiceDependencies(
    TimeProvider? TimeProvider = null,
    SecurityEventFanOutSink? SecurityEventSink = null,
    AshlarDurableTransactionProvider? TransactionProvider = null);
