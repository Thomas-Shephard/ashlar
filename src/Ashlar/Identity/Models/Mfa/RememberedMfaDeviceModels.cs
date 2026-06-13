using Ashlar.Auditing;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Persisted remembered-device record used to skip additional verification for a trusted device.
/// </summary>
public sealed record RememberedMfaDevice
{
    /// <summary>Public identifier for remembered-device management APIs.</summary>
    public required Guid Id { get; init; }
    /// <summary>User that owns this remembered device.</summary>
    public required Guid UserId { get; init; }
    /// <summary>Tenant boundary for the owner, or <see langword="null" /> for a global user.</summary>
    public Guid? TenantId { get; init; }
    /// <summary>Non-secret lookup selector paired with the client token.</summary>
    public required string TokenSelector { get; init; }
    /// <summary>Storage-safe hash of the secret verifier; the raw remembered-device token is returned only at creation.</summary>
    public required string TokenHash { get; init; }
    /// <summary>User-facing label for the remembered device.</summary>
    public string? DisplayName { get; init; }
    /// <summary>UTC time when the device was remembered.</summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>UTC time when the token last satisfied additional verification.</summary>
    public DateTimeOffset? LastUsedAt { get; set; }
    /// <summary>UTC time after which the device is no longer accepted.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
    /// <summary>UTC time when the device was revoked, when applicable.</summary>
    public DateTimeOffset? RevokedAt { get; set; }
    /// <summary>Provider-neutral, display-safe revocation reason. Do not include secrets, tokens, or credentials.</summary>
    public string? RevocationReason { get; set; }
    /// <summary>Returns whether the device is active at the supplied timestamp.</summary>
    /// <param name="now">The timestamp used for expiry evaluation.</param>
    /// <returns><see langword="true" /> when the device is active.</returns>
    public bool IsActive(DateTimeOffset now) => RevokedAt == null && ExpiresAt > now;
}

/// <summary>
/// Request to create a remembered MFA device.
/// </summary>
public sealed record CreateRememberedMfaDeviceRequest
{
    /// <summary>Tenant scope. Omit or use <see cref="TenantContext.Global" /> for global users; this API does not use <see langword="null" /> as an all-tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Optional user-facing label for the remembered device.</summary>
    public string? DisplayName { get; init; }
    /// <summary>Requested lifetime, capped by configured remembered-device limits.</summary>
    public TimeSpan? Lifetime { get; init; }
    /// <summary>Audit metadata recorded with the remembered-device operation.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to validate a remembered MFA <paramref name="Token" />.
/// </summary>
/// <param name="Token">The raw remembered MFA device token presented by the client. Do not log or persist this value.</param>
public sealed record ValidateRememberedMfaDeviceRequest(string? Token)
{
    /// <summary>Tenant scope. Omit or use <see cref="TenantContext.Global" /> for global users; this API does not use <see langword="null" /> as an all-tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Audit metadata recorded with the remembered-device operation.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to list remembered MFA devices.
/// </summary>
public sealed record ListRememberedMfaDevicesRequest
{
    /// <summary>Tenant scope. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Whether the list should include every tenant scope. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }
    /// <summary>Whether only active devices should be returned.</summary>
    public bool ActiveOnly { get; init; } = true;
}

/// <summary>
/// Request to revoke one remembered MFA device.
/// </summary>
/// <param name="DeviceId">Public identifier returned by remembered-device management APIs.</param>
public sealed record RevokeRememberedMfaDeviceRequest(Guid DeviceId)
{
    /// <summary>Tenant scope. Omit or use <see cref="TenantContext.Global" /> for global users; this API does not use <see langword="null" /> as an all-tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Optional provider-neutral, display-safe reason recorded with audit events. Do not include secrets, tokens, or credentials.</summary>
    public string? Reason { get; init; }
    /// <summary>Audit metadata recorded with the remembered-device operation.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to revoke all remembered MFA devices for a user.
/// </summary>
public sealed record RevokeAllRememberedMfaDevicesRequest
{
    /// <summary>Tenant scope. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Whether revocation should apply across every tenant scope. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }
    /// <summary>Optional provider-neutral, display-safe reason recorded with audit events. Do not include secrets, tokens, or credentials.</summary>
    public string? Reason { get; init; }
    /// <summary>Audit metadata recorded with the remembered-device operation.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Safe remembered MFA device metadata.
/// </summary>
/// <param name="Id">Public identifier returned by remembered-device management APIs.</param>
/// <param name="UserId">User that owns the remembered device.</param>
/// <param name="TenantId">Tenant boundary for the owner, or <see langword="null" /> for a global user.</param>
/// <param name="DisplayName">User-facing label for the remembered device, when supplied.</param>
/// <param name="CreatedAt">UTC time when the device was remembered.</param>
/// <param name="LastUsedAt">UTC time when the token last satisfied additional verification, when known.</param>
/// <param name="ExpiresAt">UTC time after which the device is no longer accepted.</param>
/// <param name="RevokedAt">UTC time when the device was revoked, when applicable.</param>
/// <param name="RevocationReason">Provider-neutral, display-safe revocation reason.</param>
/// <param name="IsActive">Whether the device is active.</param>
public sealed record RememberedMfaDeviceSummary(
    Guid Id,
    Guid UserId,
    Guid? TenantId,
    string? DisplayName,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? RevokedAt,
    string? RevocationReason,
    bool IsActive);

/// <summary>
/// Creation result containing the raw <paramref name="Token" /> exactly once.
/// </summary>
/// <param name="Device">Safe remembered MFA entry summary returned to the caller.</param>
/// <param name="Token">The raw remembered MFA token. Return it once to the client; do not log or persist this value.</param>
public sealed record RememberedMfaDeviceCreated(RememberedMfaDeviceSummary Device, string Token);

/// <summary>
/// Validation status for a remembered MFA device token.
/// </summary>
public enum RememberedMfaDeviceValidationStatus
{
    /// <summary>The token was valid.</summary>
    Succeeded = 0,
    /// <summary>The token could not be validated.</summary>
    Failed = 1,
    /// <summary>The device is expired.</summary>
    Expired = 2,
    /// <summary>The device is revoked.</summary>
    Revoked = 3,
    /// <summary>The device belongs to a different user.</summary>
    WrongUser = 4,
    /// <summary>The device belongs to a different tenant scope.</summary>
    WrongTenant = 5
}

/// <summary>
/// Result of remembered MFA <paramref name="Device" /> validation.
/// </summary>
/// <param name="Succeeded">Whether validation succeeded.</param>
/// <param name="Device">Safe remembered MFA entry summary, when validation can expose one.</param>
/// <param name="Status">Outcome of remembered MFA token validation.</param>
public sealed record ValidateRememberedMfaDeviceResult(
    bool Succeeded,
    RememberedMfaDeviceSummary? Device,
    RememberedMfaDeviceValidationStatus Status)
{
    /// <summary>Gets a generic failed validation result.</summary>
    public static ValidateRememberedMfaDeviceResult Failed { get; } = new(false, null, RememberedMfaDeviceValidationStatus.Failed);
}

/// <summary>
/// Options for remembered MFA device tokens.
/// </summary>
public sealed class RememberedMfaDeviceOptions
{
    /// <summary>Lifetime used when create requests do not specify one.</summary>
    public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromDays(30);
    /// <summary>Upper bound for caller-requested remembered-device lifetimes.</summary>
    public TimeSpan MaxLifetime { get; set; } = TimeSpan.FromDays(365);
    /// <summary>Maximum active remembered devices allowed per user and tenant scope.</summary>
    public int MaxActiveDevicesPerUser { get; set; } = 20;
    /// <summary>Random byte length for the non-secret token selector.</summary>
    public int SelectorByteLength { get; set; } = 32;
    /// <summary>Random byte length for the secret token verifier.</summary>
    public int VerifierByteLength { get; set; } = 32;
    /// <summary>Maximum stored length for user-facing device labels.</summary>
    public int MaxDisplayNameLength { get; set; } = 128;
    /// <summary>Maximum stored length for display-safe revocation reasons.</summary>
    public int MaxRevocationReasonLength { get; set; } = 512;

    /// <summary>Returns whether the options are valid.</summary>
    /// <param name="options">The options to validate.</param>
    /// <returns><see langword="true" /> when the options are valid.</returns>
    public static bool Validate(RememberedMfaDeviceOptions? options)
    {
        return options != null
            && options.DefaultLifetime > TimeSpan.Zero
            && options.MaxLifetime >= options.DefaultLifetime
            && options.MaxActiveDevicesPerUser > 0
            && options.SelectorByteLength is >= ISecureTokenGenerator.MinimumByteLength and <= ISecureTokenGenerator.MaximumByteLength
            && options.VerifierByteLength is >= ISecureTokenGenerator.MinimumByteLength and <= ISecureTokenGenerator.MaximumByteLength
            && options.MaxDisplayNameLength > 0
            && options.MaxRevocationReasonLength > 0;
    }
}
