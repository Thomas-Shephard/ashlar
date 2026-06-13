namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Manages remembered MFA devices without treating them as credentials or authentication factors.
/// </summary>
public interface IRememberedMfaDeviceService
{
    /// <summary>
    /// Creates a remembered MFA device after the same user has completed a fresh MFA ceremony.
    /// </summary>
    /// <param name="mfaResult">Successful fresh MFA result for the session owner that will own the remembered device.</param>
    /// <param name="request">Tenant scope, audit context, device label, and lifetime for the remembered device.</param>
    /// <param name="cancellationToken">A token that can cancel device creation.</param>
    /// <returns>Created device metadata and raw token returned once to the caller, or a failure status.</returns>
    /// <remarks>
    /// Hosts must pass the result produced by Ashlar's MFA orchestration for the current sign-in or
    /// step-up flow. The service rejects missing users, unsuccessful results, and results that did
    /// not satisfy fresh MFA; remembered devices are never created as an administrative action and
    /// are not valid for strict step-up. Raw remembered-device tokens are returned only in the
    /// successful creation result and must not be logged or persisted by host code.
    /// </remarks>
    Task<Result<RememberedMfaDeviceCreated>> CreateAfterSuccessfulMfaAsync(MfaAuthenticationResult mfaResult, CreateRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a raw remembered MFA device token for the supplied user context.
    /// </summary>
    /// <param name="userId">User expected to own the remembered-device token.</param>
    /// <param name="request">Raw token, tenant scope, and audit context for the validation attempt. Do not log or persist the token.</param>
    /// <param name="cancellationToken">A token that can cancel token validation.</param>
    /// <returns>Validation outcome and matching remembered device metadata when the token is accepted.</returns>
    Task<ValidateRememberedMfaDeviceResult> ValidateAsync(Guid userId, ValidateRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists safe remembered MFA device metadata for a user.
    /// </summary>
    /// <param name="userId">User whose remembered devices should be listed.</param>
    /// <param name="request">Tenant scope and all-tenant flag for the device list.</param>
    /// <param name="cancellationToken">A token that can cancel device listing.</param>
    /// <returns>Safe remembered device summaries.</returns>
    Task<IReadOnlyList<RememberedMfaDeviceSummary>> ListAsync(Guid userId, ListRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single remembered MFA device owned by a user and records a security event for the attempt.
    /// </summary>
    /// <param name="userId">User that must own the remembered device.</param>
    /// <param name="request">Device identifier, tenant scope, display-safe revocation reason, and audit context.</param>
    /// <param name="cancellationToken">A token that can cancel device revocation.</param>
    /// <returns><see langword="true" /> when a device was revoked.</returns>
    Task<bool> RevokeAsync(Guid userId, RevokeRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all remembered MFA devices for a user and records a security event for the attempt.
    /// </summary>
    /// <param name="userId">User whose remembered devices should be revoked.</param>
    /// <param name="request">Tenant scope, all-tenant flag, display-safe revocation reason, and audit context.</param>
    /// <param name="cancellationToken">A token that can cancel bulk device revocation.</param>
    /// <returns>The number of revoked devices.</returns>
    Task<int> RevokeAllAsync(Guid userId, RevokeAllRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default);
}
