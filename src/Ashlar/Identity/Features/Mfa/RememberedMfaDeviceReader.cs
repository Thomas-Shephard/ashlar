namespace Ashlar.Identity.Features.Mfa;

internal sealed class RememberedMfaDeviceReader(IRememberedMfaDeviceRepository repository, TimeProvider? timeProvider = null)
    : IRememberedMfaDeviceReader
{
    private readonly IRememberedMfaDeviceRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<IReadOnlyList<RememberedMfaDeviceSummary>> ListAsync(Guid userId, ListRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        if (request.Tenant != null && request.IncludeAllTenants)
            throw new ArgumentException("Tenant scope cannot be combined with IncludeAllTenants = true.", nameof(request));

        var tenant = request.IncludeAllTenants ? null : request.Tenant ?? TenantContext.Global;
        var now = _timeProvider.GetUtcNow();
        return (await _repository.ListForUserAsync(userId, tenant, request.ActiveOnly, now, cancellationToken))
            .Select(device => new RememberedMfaDeviceSummary(device.Id, device.UserId, device.TenantId, device.DisplayName,
                device.CreatedAt, device.LastUsedAt, device.ExpiresAt, device.RevokedAt, device.RevocationReason, device.IsActive(now)))
            .ToList().AsReadOnly();
    }
}
