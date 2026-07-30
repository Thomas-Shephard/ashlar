using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Invitations;

/// <summary>
/// Implements administrator invitation creation and revocation operations.
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
    private readonly AccountSecurityOperationBoundary _createBoundary;
    private readonly IInvitationMutationExecutor _mutations;

    /// <summary>Initializes invitation mutations with durable audit composition.</summary>
    public InvitationAdministrationService(
        IInvitationRepository repository,
        InvitationAdministrationServiceDependencies dependencies,
        IInvitationMutationExecutor mutations,
        IAuthenticationSessionRepository sessions,
        IAccountSecurityOperationAuthorizer authorizer,
        IPersistentSecurityEventSink auditSink)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _mutations = mutations ?? throw new ArgumentNullException(nameof(mutations));
        ArgumentNullException.ThrowIfNull(dependencies);
        _transactionProvider = dependencies.TransactionProvider ?? throw new ArgumentNullException(nameof(dependencies));
        _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(
            DurableSecurityMutationComposition.Require(dependencies.SecurityEventSink, _transactionProvider, "Invitation revocation", repository),
            _timeProvider);
        _boundary = new(sessions, authorizer, auditSink, _timeProvider,
            IInvitationAdministrationService.RevokeProofPurpose, AshlarSecurityEventTypes.InvitationRevoked);
        _createBoundary = new(sessions, authorizer, auditSink, _timeProvider,
            IInvitationAdministrationService.CreateProofPurpose, AshlarSecurityEventTypes.InvitationCreated);
    }

    /// <inheritdoc />
    public async Task<Result> CreateInvitationAsync(AccountSecurityActorContext actor, CreateInvitationAdministrationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        try
        {
            CreateInvitationAdministrationRequest.ThrowIfInvalid(request);
            _mutations.ValidateCreateInvitation(request.Invitation, request.CallbackBaseUri);
        }
        catch (ArgumentException exception)
        {
            return Result.Failure(AshlarFailureCodes.ValidationError, exception.Message);
        }

        if (!await _createBoundary.AuthorizeAsync(actor, request.Tenant, false, Guid.Empty,
                AccountSecurityOperation.CreateInvitation, cancellationToken))
            return Result.Failure(AshlarFailureCodes.ValidationError);

        var audit = actor.Audit;
        var context = new AuthenticationContext(TenantId: request.Tenant.TenantId, IpAddress: audit.IpAddress,
            UserAgent: audit.UserAgent, CorrelationId: audit.CorrelationId, UserId: actor.ActorUserId,
            CurrentSessionId: actor.CurrentSessionId);
        return await _mutations.CreateInvitationAsync(request.Invitation, request.CallbackBaseUri, context, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<Result<RevokeInvitationsByEmailAdministrationResult>> RevokeInvitationsByEmailAsync(AccountSecurityActorContext actor, RevokeInvitationsByEmailAdministrationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            _mutations.ValidateRevokeInvitationsByEmail(request);
        }
        catch (ArgumentException exception)
        {
            return Result.Failure<RevokeInvitationsByEmailAdministrationResult>(AshlarFailureCodes.ValidationError, exception.Message);
        }

        if (!await _boundary.AuthorizeAsync(actor, request.Tenant, request.IncludeAllTenants, Guid.Empty,
                AccountSecurityOperation.RevokeInvitationsByEmail, cancellationToken))
            return Result.Failure<RevokeInvitationsByEmailAdministrationResult>(AshlarFailureCodes.ValidationError);

        var result = await _mutations.RevokeInvitationsByEmailAsync(request, actor.Audit, actor.CurrentSessionId, cancellationToken);
        if (!result.Succeeded)
            await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.RevokeInvitationsByEmail);
        return result;
    }

    /// <inheritdoc />
    public async Task<Result<RevokeInvitationByIdAdministrationResult>> RevokeInvitationByIdAsync(AccountSecurityActorContext actor, RevokeInvitationByIdAdministrationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateRevokeRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (request.Reason?.Length > MaximumReasonLength)
        {
            return Result.Failure<RevokeInvitationByIdAdministrationResult>(AshlarFailureCodes.ValidationError, $"Reason cannot exceed {MaximumReasonLength} characters.");
        }
        if (!await _boundary.AuthorizeAsync(actor, request.Tenant, request.IncludeAllTenants, Guid.Empty,
                AccountSecurityOperation.RevokeInvitationById, cancellationToken))
            return Result.Failure<RevokeInvitationByIdAdministrationResult>(AshlarFailureCodes.ValidationError);

        var now = _timeProvider.GetUtcNow();
        RevokeInvitationByIdAdministrationResult? result;
        await using (var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken))
        {
            result = await _repository.RevokeInvitationByIdAsync(request, now, cancellationToken);
            if (result != null && result.InvitationId == request.InvitationId
                && AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, result.TenantId))
            {
                await RecordRevocationAttemptAsync(actor, request, result, cancellationToken);

                await transaction.CommitAsync(cancellationToken);
                return Result.Success(result);
            }
        }

        await _boundary.RecordFailureAsync(actor, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.RevokeInvitationById);
        return Result.Failure<RevokeInvitationByIdAdministrationResult>(AshlarFailureCodes.InvitationNotFound, "Invitation was not found.");
    }

    private Task RecordRevocationAttemptAsync(
        AccountSecurityActorContext actor,
        RevokeInvitationByIdAdministrationRequest request,
        RevokeInvitationByIdAdministrationResult result,
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
            SessionId = actor.CurrentSessionId,
            Audit = actor.Audit,
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

    private static bool TryValidateRevokeRequest(RevokeInvitationByIdAdministrationRequest request, out Result<RevokeInvitationByIdAdministrationResult> failure)
    {
        try
        {
            RevokeInvitationByIdAdministrationRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<RevokeInvitationByIdAdministrationResult>(AshlarFailureCodes.ValidationError, exception.Message);
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
