using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;

namespace Ashlar.Identity.Features.Administration;

internal sealed class AuthenticationRateLimitAdministrationService : IAuthenticationRateLimitAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IAuthenticationRateLimitAdministrationRepository _repository;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly AshlarDurableTransactionProvider _transactionProvider;
    private readonly AccountSecurityOperationBoundary _boundary;
    private readonly TimeProvider _timeProvider;

    public AuthenticationRateLimitAdministrationService(
        IAuthenticationRateLimitAdministrationRepository repository,
        AuthenticationRateLimitAdministrationServiceDependencies dependencies,
        IAuthenticationSessionRepository sessions,
        IAccountSecurityOperationAuthorizer authorizer,
        IPersistentSecurityEventSink auditSink)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        ArgumentNullException.ThrowIfNull(dependencies);
        _transactionProvider = dependencies.TransactionProvider ?? throw new ArgumentNullException(nameof(dependencies));
        _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(
            DurableSecurityMutationComposition.Require(
                dependencies.SecurityEventSink,
                _transactionProvider,
                "Authentication rate-limit resets",
                repository),
            dependencies.TimeProvider);
        _boundary = new(sessions, authorizer, auditSink, _timeProvider,
            IAccountSecurityAdministrationService.ProofPurpose, AshlarSecurityEventTypes.AuthenticationRateLimitBucketReset);
    }

    public async Task<Result<AuthenticationRateLimitBucketResetResult>> ResetBucketAsync(AccountSecurityActorContext actor, TenantContext? tenant,
        bool includeAllTenants, ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateResetRequest(request, out var validationFailure))
        {
            return validationFailure;
        }
        try { AdministrationScopeValidation.ThrowIfInvalidScope(tenant, includeAllTenants); }
        catch (ArgumentException exception) { return Result.Failure<AuthenticationRateLimitBucketResetResult>(AshlarFailureCodes.ValidationError, exception.Message); }
        if (request.Audit.ActorUserId != actor.ActorUserId)
        {
            await _boundary.RecordFailureAsync(actor, tenant, includeAllTenants, AccountSecurityOperation.ResetAuthenticationRateLimitBucket);
            return Result.Failure<AuthenticationRateLimitBucketResetResult>(AshlarFailureCodes.ValidationError);
        }
        if (!await _boundary.AuthorizeAsync(actor, tenant, includeAllTenants, Guid.Empty,
                AccountSecurityOperation.ResetAuthenticationRateLimitBucket, cancellationToken))
            return Result.Failure<AuthenticationRateLimitBucketResetResult>(AshlarFailureCodes.ValidationError);

        var bucket = await _repository.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest(request.BucketId, request.Purpose),
            _timeProvider.GetUtcNow(), cancellationToken);
        if (bucket is not null && (!string.Equals(bucket.BucketId, request.BucketId, StringComparison.Ordinal)
            || !string.Equals(bucket.Purpose, request.Purpose, StringComparison.Ordinal)))
        {
            await _boundary.RecordFailureAsync(actor, tenant, includeAllTenants, AccountSecurityOperation.ResetAuthenticationRateLimitBucket);
            return Result.Failure<AuthenticationRateLimitBucketResetResult>(AshlarFailureCodes.RateLimitBucketNotFound);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        AuthenticationRateLimitBucketResetResult result;
        if (bucket is null)
        {
            result = new AuthenticationRateLimitBucketResetResult(request.BucketId, request.Purpose,
                AuthenticationRateLimitBucketResetStatus.NotFound);
        }
        else
        {
            try
            {
                var reset = await _repository.ResetBucketAsync(request, cancellationToken);
                var status = reset ? AuthenticationRateLimitBucketResetStatus.Reset : AuthenticationRateLimitBucketResetStatus.NotFound;
                result = new AuthenticationRateLimitBucketResetResult(request.BucketId, request.Purpose, status);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                result = new AuthenticationRateLimitBucketResetResult(
                    request.BucketId,
                    request.Purpose,
                    AuthenticationRateLimitBucketResetStatus.Failed);
            }
        }

        await RecordResetAttemptAsync(request, result.Status, cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return Result.Success(result);
    }

    private Task RecordResetAttemptAsync(
        ResetAuthenticationRateLimitBucketRequest request,
        AuthenticationRateLimitBucketResetStatus status,
        CancellationToken cancellationToken)
    {
        var outcome = status == AuthenticationRateLimitBucketResetStatus.Reset
            ? SecurityEventOutcomes.Success
            : SecurityEventOutcomes.Failure;

        return _securityEvents.RecordAsync(
            new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationRateLimitBucketReset,
                Audit = request.Audit,
                Outcome = outcome,
                Properties = CreateResetAttemptProperties(request, status)
            },
            cancellationToken);
    }

    private static Dictionary<string, string> CreateResetAttemptProperties(
        ResetAuthenticationRateLimitBucketRequest request,
        AuthenticationRateLimitBucketResetStatus status)
    {
        return new Dictionary<string, string>
        {
            ["purpose"] = request.Purpose,
            ["bucket_id"] = request.BucketId,
            ["reset_status"] = status.ToString()
        };
    }

    internal static bool TryValidateSearchRequest(SearchAuthenticationRateLimitBucketsRequest request, out Result<AuthenticationRateLimitBucketSearchResult> failure)
    {
        try
        {
            SearchAuthenticationRateLimitBucketsRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationRateLimitBucketSearchResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    internal static bool TryValidateLookupRequest(AuthenticationRateLimitBucketLookupRequest request, out Result<AuthenticationRateLimitBucketSummary> failure)
    {
        try
        {
            AuthenticationRateLimitBucketLookupRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationRateLimitBucketSummary>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool TryValidateResetRequest(ResetAuthenticationRateLimitBucketRequest request, out Result<AuthenticationRateLimitBucketResetResult> failure)
    {
        try
        {
            ResetAuthenticationRateLimitBucketRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthenticationRateLimitBucketResetResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}

internal sealed record AuthenticationRateLimitAdministrationServiceDependencies(
    TimeProvider? TimeProvider = null,
    SecurityEventFanOutSink? SecurityEventSink = null,
    AshlarDurableTransactionProvider? TransactionProvider = null);
