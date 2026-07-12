namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Lists safe remembered MFA device metadata without enabling device mutation.</summary>
public interface IRememberedMfaDeviceReader
{
    /// <summary>Lists safe remembered MFA device metadata for a user.</summary>
    /// <param name="userId">User whose remembered devices should be listed.</param>
    /// <param name="request">Tenant scope and all-tenant flag for the device list.</param>
    /// <param name="cancellationToken">A token that can cancel device listing.</param>
    /// <returns>Safe remembered device summaries.</returns>
    Task<IReadOnlyList<RememberedMfaDeviceSummary>> ListAsync(Guid userId, ListRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default);
}
