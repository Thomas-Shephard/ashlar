using Ashlar.Auditing;
using Ashlar.Security.Tokens;

namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Represents a durable remembered MFA device record.
/// </summary>
public sealed record RememberedMfaDevice
{
    /// <summary>Gets the public device identifier.</summary>
    public required Guid Id { get; init; }
    /// <summary>Gets the owning user identifier.</summary>
    public required Guid UserId { get; init; }
    /// <summary>Gets the tenant identifier, or <see langword="null" /> for global users.</summary>
    public Guid? TenantId { get; init; }
    /// <summary>Gets the public token selector used for lookup.</summary>
    public required string TokenSelector { get; init; }
    /// <summary>Gets the hash of the secret verifier.</summary>
    public required string TokenHash { get; init; }
    /// <summary>Gets the informational display name.</summary>
    public string? DisplayName { get; init; }
    /// <summary>Gets the creation timestamp.</summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>Gets or sets the last successful use timestamp.</summary>
    public DateTimeOffset? LastUsedAt { get; set; }
    /// <summary>Gets the expiry timestamp.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
    /// <summary>Gets or sets the revocation timestamp.</summary>
    public DateTimeOffset? RevokedAt { get; set; }
    /// <summary>Gets or sets the revocation reason.</summary>
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
    /// <summary>Gets the tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Gets the informational display name.</summary>
    public string? DisplayName { get; init; }
    /// <summary>Gets the requested device lifetime.</summary>
    public TimeSpan? Lifetime { get; init; }
    /// <summary>Gets the audit context.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to validate a remembered MFA <paramref name="Token" />.
/// </summary>
/// <param name="Token">The raw remembered MFA entry token.</param>
public sealed record ValidateRememberedMfaDeviceRequest(string Token)
{
    /// <summary>Gets the tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Gets the audit context.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to list remembered MFA devices.
/// </summary>
public sealed record ListRememberedMfaDevicesRequest
{
    /// <summary>Gets the tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Gets whether the list should include every tenant scope.</summary>
    public bool IncludeAllTenants { get; init; }
    /// <summary>Gets whether only active devices should be returned.</summary>
    public bool ActiveOnly { get; init; } = true;
}

/// <summary>
/// Request to revoke one remembered MFA device.
/// </summary>
/// <param name="DeviceId">The public device identifier.</param>
public sealed record RevokeRememberedMfaDeviceRequest(Guid DeviceId)
{
    /// <summary>Gets the tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Gets the revocation reason.</summary>
    public string? Reason { get; init; }
    /// <summary>Gets the audit context.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Request to revoke all remembered MFA devices for a user.
/// </summary>
public sealed record RevokeAllRememberedMfaDevicesRequest
{
    /// <summary>Gets the tenant scope. Use <see cref="TenantContext.Global" /> for global users.</summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>Gets whether revocation should apply across all tenant scopes.</summary>
    public bool IncludeAllTenants { get; init; }
    /// <summary>Gets the revocation reason.</summary>
    public string? Reason { get; init; }
    /// <summary>Gets the audit context.</summary>
    public AuditContext? Audit { get; init; }
}

/// <summary>
/// Safe remembered MFA device metadata.
/// </summary>
/// <param name="Id">The public device identifier.</param>
/// <param name="UserId">The owning user identifier.</param>
/// <param name="TenantId">The tenant identifier.</param>
/// <param name="DisplayName">The informational display name.</param>
/// <param name="CreatedAt">The creation timestamp.</param>
/// <param name="LastUsedAt">The last successful use timestamp.</param>
/// <param name="ExpiresAt">The expiry timestamp.</param>
/// <param name="RevokedAt">The revocation timestamp.</param>
/// <param name="RevocationReason">The revocation reason.</param>
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
/// <param name="Device">The safe remembered MFA entry summary.</param>
/// <param name="Token">The raw remembered MFA entry token.</param>
public sealed record RememberedMfaDeviceCreated(RememberedMfaDeviceSummary Device, string Token);

/// <summary>
/// Validation status for a remembered MFA device token.
/// </summary>
public enum RememberedMfaDeviceValidationStatus
{
    /// <summary>The token was valid.</summary>
    Success = 0,
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
/// <param name="Device">The safe device summary.</param>
/// <param name="Status">The validation status.</param>
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
    /// <summary>Gets or sets the default device lifetime.</summary>
    public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromDays(30);
    /// <summary>Gets or sets the maximum allowed device lifetime.</summary>
    public TimeSpan MaxLifetime { get; set; } = TimeSpan.FromDays(365);
    /// <summary>Gets or sets the maximum active remembered devices per user and tenant scope.</summary>
    public int MaxActiveDevicesPerUser { get; set; } = 20;
    /// <summary>Gets or sets the selector byte length.</summary>
    public int SelectorByteLength { get; set; } = 32;
    /// <summary>Gets or sets the verifier byte length.</summary>
    public int VerifierByteLength { get; set; } = 32;
    /// <summary>Gets or sets the maximum display name length.</summary>
    public int MaxDisplayNameLength { get; set; } = 128;
    /// <summary>Gets or sets the maximum revocation reason length.</summary>
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
