using Ashlar.Auditing;

namespace Ashlar.Identity.Features.AccountSecurity;

internal sealed class AccountSecurityAdministrationService(
    IAccountSecurityMutationExecutor executor,
    IAccountSecurityOperationAuthorizer authorizer,
    TimeProvider timeProvider,
    ISecurityEventSink? securityEventSink) : IAccountSecurityAdministrationService
{
    private readonly TimeProvider _timeProvider = timeProvider;
    private readonly SecurityEventEmitter _securityEvents = new(securityEventSink, timeProvider);

    public Task<Result<AccountSecurityOperationResult>> SetUserAccountStateAsync(SetUserAccountStateAdministrationRequest request, CancellationToken cancellationToken = default) =>
        ExecuteAsync(request, AccountSecurityOperation.SetAccountState, AshlarSecurityEventTypes.UserAccountStateChanged, () => executor.SetUserAccountStateAsync(request.TargetUserId,
            new SetUserAccountStateRequest(request.AccountState, request.Audit,
                request.Tenant, request.Reason, request.RevokeSessionsAndRememberedMfaDevices, request.IncludeAllTenants), cancellationToken), cancellationToken);

    public Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(AccountSecurityAdministrationRequest request, CancellationToken cancellationToken = default) =>
        ExecuteAsync(request, AccountSecurityOperation.RevokeSessions, AshlarSecurityEventTypes.SessionsRevokedForUser, () => executor.RevokeSessionsAsync(request.TargetUserId, ToExecutorRequest(request), cancellationToken), cancellationToken);

    public Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(RevokeAccountCredentialsRequest request, CancellationToken cancellationToken = default) =>
        ExecuteAsync(request, AccountSecurityOperation.RevokeCredentials, AshlarSecurityEventTypes.UserCredentialsRevoked, () => executor.RevokeCredentialsAsync(request.TargetUserId, request.Provider, ToExecutorRequest(request), cancellationToken), cancellationToken);

    public Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(AccountSecurityAdministrationRequest request, CancellationToken cancellationToken = default) =>
        ExecuteAsync(request, AccountSecurityOperation.ResetMfa, AshlarSecurityEventTypes.UserMfaReset, () => executor.ResetMfaAsync(request.TargetUserId, ToExecutorRequest(request), cancellationToken), cancellationToken);

    public Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDeviceAsync(RevokeRememberedMfaDeviceAdministrationRequest request, CancellationToken cancellationToken = default) =>
        ExecuteAsync(request, AccountSecurityOperation.RevokeRememberedMfaDevice, AshlarSecurityEventTypes.RememberedMfaDeviceRevoked,
            () => executor.RevokeRememberedMfaDeviceAsync(request.TargetUserId, request.DeviceId, ToExecutorRequest(request), cancellationToken), cancellationToken);

    public Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDevicesAsync(AccountSecurityAdministrationRequest request, CancellationToken cancellationToken = default) =>
        ExecuteAsync(request, AccountSecurityOperation.RevokeRememberedMfaDevices, AshlarSecurityEventTypes.RememberedMfaDevicesRevoked,
            () => executor.RevokeRememberedMfaDevicesAsync(request.TargetUserId, ToExecutorRequest(request), cancellationToken), cancellationToken);

    private async Task<Result<AccountSecurityOperationResult>> ExecuteAsync(AccountSecurityAdministrationRequest request, AccountSecurityOperation operation, string eventType,
        Func<Task<Result<AccountSecurityOperationResult>>> execute, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Audit.ActorUserId != request.ActorUserId)
            return await RejectAsync(request, eventType, AshlarFailureCodes.ValidationError,
                "Audit actor must match the authenticated actor.", cancellationToken);

        var proofFailure = FreshVerificationProofValidator.ValidateMfaProof(request.ActorUserId, request.ActorTenant, request.FreshMfaProof,
            request.CurrentSessionId, _timeProvider.GetUtcNow());
        if (proofFailure is { } failure)
            return await RejectAsync(request, eventType, failure, cancellationToken: cancellationToken);

        var authorized = await authorizer.AuthorizeAsync(CreateAuthorizationContext(request, operation), cancellationToken);
        if (!authorized)
            return await RejectAsync(request, eventType, AshlarFailureCodes.ValidationError,
                "Account-security operation was not authorized.", cancellationToken);

        return await execute();
    }

    private async Task<Result<AccountSecurityOperationResult>> RejectAsync(
        AccountSecurityAdministrationRequest request,
        string eventType,
        AshlarFailureCode failure,
        string? message = null,
        CancellationToken cancellationToken = default)
    {
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = request.TargetUserId,
            TenantId = request.Tenant?.TenantId,
            Audit = request.Audit,
            FailureReason = failure.Value
        }, cancellationToken);
        return Result.Failure<AccountSecurityOperationResult>(failure, message);
    }

    private static AccountSecurityOperationRequest ToExecutorRequest(AccountSecurityAdministrationRequest request) =>
        new(request.Audit, request.Tenant, request.Reason, request.IncludeAllTenants,
            (request as RevokeAccountCredentialsRequest)?.PreservePrimarySignInMethod ?? false);

    private static AccountSecurityAuthorizationContext CreateAuthorizationContext(
        AccountSecurityAdministrationRequest request,
        AccountSecurityOperation operation) =>
        new(
            request.ActorUserId,
            request.ActorTenant,
            request.TargetUserId,
            request.Tenant,
            request.IncludeAllTenants,
            operation,
            Provider: (request as RevokeAccountCredentialsRequest)?.Provider,
            AccountState: (request as SetUserAccountStateAdministrationRequest)?.AccountState,
            RevokeSessionsAndRememberedMfaDevices: (request as SetUserAccountStateAdministrationRequest)?.RevokeSessionsAndRememberedMfaDevices,
            PreservePrimarySignInMethod: (request as RevokeAccountCredentialsRequest)?.PreservePrimarySignInMethod ?? false,
            RememberedMfaDeviceId: (request as RevokeRememberedMfaDeviceAdministrationRequest)?.DeviceId,
            CurrentSessionId: request.CurrentSessionId);
}
