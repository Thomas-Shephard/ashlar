namespace Ashlar.Identity.Features.AccountSecurity;

internal interface IAccountSecurityMutationExecutor
{
    Task<Result<AccountSecurityOperationResult>> SetUserAccountStateAsync(Guid userId, SetUserAccountStateRequest request, CancellationToken cancellationToken = default);
    Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);
    Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);
    Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);
    Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDeviceAsync(Guid userId, Guid deviceId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);
    Task<Result<AccountSecurityOperationResult>> RevokeRememberedMfaDevicesAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default);
}

internal interface IAccountSecurityPostureReader
{
    Task<Result<AccountSecurityPosture>> GetUserSecurityPostureAsync(
        Guid userId, AccountSecurityPostureRequest request, CancellationToken cancellationToken = default);
}
