namespace Ashlar.Identity.Features.Administration;

/// <summary>
/// Implements destructive administrator account recovery execution by delegating to account security operations.
/// </summary>
/// <param name="accountSecurityService">The account security service that owns mutation behavior.</param>
/// <remarks>
/// These operations are intended for administrative account recovery tooling and do not authorize the caller.
/// Host applications must protect usage with administrator authorization and fresh step-up policy.
/// </remarks>
public sealed class AccountRecoveryAdministrationExecutor(IAccountSecurityService accountSecurityService)
    : IAccountRecoveryAdministrationExecutor
{
    private readonly IAccountSecurityService _accountSecurityService = accountSecurityService ?? throw new ArgumentNullException(nameof(accountSecurityService));

    /// <inheritdoc />
    public Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(
        AccountRecoveryResetMfaRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.ThrowIfInvalid();
        return _accountSecurityService.ResetMfaAsync(request.UserId, ToAccountSecurityRequest(request), cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(
        AccountRecoveryRevokeSessionsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.ThrowIfInvalid();
        return _accountSecurityService.RevokeSessionsAsync(request.UserId, ToAccountSecurityRequest(request), cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<AccountSecurityOperationResult>> RevokeProviderCredentialsAsync(
        AccountRecoveryRevokeProviderCredentialsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.ThrowIfInvalid();
        return _accountSecurityService.RevokeCredentialsAsync(request.UserId, request.Provider, ToAccountSecurityRequest(request), cancellationToken);
    }

    private static AccountSecurityOperationRequest ToAccountSecurityRequest(AccountRecoveryExecutionRequest request)
    {
        return new AccountSecurityOperationRequest(request.Audit, request.Tenant, request.Reason, request.IncludeAllTenants);
    }
}
