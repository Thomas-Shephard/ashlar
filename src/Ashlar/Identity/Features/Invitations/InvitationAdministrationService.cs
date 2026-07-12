using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Invitations;

/// <summary>
/// Implements administrator invitation search, single-item lookup, and revocation operations.
/// </summary>
/// <param name="repository">Repository used for safe administrator invitation lookup and mutation.</param>
/// <param name="dependencies">Optional clock and audit dependencies.</param>
/// <remarks>
/// These operations are intended for administrative diagnostics and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
internal sealed class InvitationAdministrationService(
    IInvitationRepository repository,
    InvitationAdministrationServiceDependencies dependencies) : IInvitationAdministrationService
{
    internal const int MaximumLimit = 100;
    internal const int MaximumReasonLength = 512;

    private readonly IInvitationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly InvitationAdministrationServiceDependencies _dependencies = dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly TimeProvider _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
    private readonly IAshlarDurableTransactionProvider _transactionProvider = dependencies.TransactionProvider ?? throw new ArgumentNullException(nameof(dependencies));
    private readonly SecurityEventEmitter _securityEvents = new(DurableSecurityMutationComposition.Require(dependencies.SecurityEventSink, dependencies.TransactionProvider, "Invitation revocation"), dependencies.TimeProvider ?? TimeProvider.System);

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
        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var result = await _repository.RevokeInvitationAsync(request, now, cancellationToken);
        if (result == null)
        {
            return Result.Failure<RevokeInvitationAdministrationResult>(AshlarFailureCodes.InvitationNotFound, "Invitation was not found.");
        }

        if (result.RevocationStatus == InvitationAdministrationRevocationStatus.Revoked)
        {
            await RecordRevocationAsync(request, result, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);

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
            Outcome = SecurityEventOutcomes.Success,
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
    IAshlarDurableTransactionProvider? TransactionProvider = null);
