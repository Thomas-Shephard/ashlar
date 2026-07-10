namespace Ashlar.Identity.Features.Mfa;

internal interface IRememberedMfaDeviceMutationExecutor
{
    Task<bool> RevokeAsync(Guid userId, RevokeRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default);
    Task<int> RevokeAllAsync(Guid userId, RevokeAllRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default);
}
