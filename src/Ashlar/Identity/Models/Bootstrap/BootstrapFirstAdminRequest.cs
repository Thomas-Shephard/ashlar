using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Bootstrap;

/// <summary>
/// Describes the first administrator to create during installation bootstrap.
/// </summary>
public sealed class BootstrapFirstAdminRequest
{
    /// <summary>
    /// Email address for the first administrator account. Ashlar stores a sanitized display/delivery address and uses a separate normalized form for lookup and uniqueness checks.
    /// </summary>
    public required string Email { get; init; }
    /// <summary>
    /// Optional display name for the first administrator account.
    /// </summary>
    public string? UserName { get; init; }
    /// <summary>
    /// Tenant boundary for tenant-scoped bootstrap.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Audit metadata recorded with the bootstrap request.
    /// </summary>
    public AuditContext? Audit { get; init; }
    /// <summary>
    /// Operator-controlled setup secret required to authorize first-admin bootstrap. Do not log this value.
    /// </summary>
    public string? SetupSecret { get; init; }
}
