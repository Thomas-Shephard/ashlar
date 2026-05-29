using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Bootstrap;

/// <summary>
/// Describes the first administrator to create during installation bootstrap.
/// </summary>
public sealed class BootstrapFirstAdminRequest
{
    /// <summary>
    /// Gets or sets the administrator email address.
    /// </summary>
    public required string Email { get; init; }
    /// <summary>
    /// Gets or sets the optional display name for the administrator.
    /// </summary>
    public string? UserName { get; init; }
    /// <summary>
    /// Gets or sets the tenant boundary for tenant-scoped bootstrap.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Gets or sets audit metadata for the request.
    /// </summary>
    public AuditContext? Audit { get; init; }
    /// <summary>
    /// Gets or sets the operator-controlled setup secret used to authorize bootstrap.
    /// </summary>
    public string? SetupSecret { get; init; }
}
