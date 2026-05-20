using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Bootstrap;

/// <summary>
/// Provides create bootstrap invitation request behavior.
/// </summary>
public sealed class CreateBootstrapInvitationRequest
{
    /// <summary>
    /// Gets or sets the email value.
    /// </summary>
    public required string Email { get; init; }
    /// <summary>
    /// Gets or sets the user name value.
    /// </summary>
    public string? UserName { get; init; }
    /// <summary>
    /// Gets or sets the tenant id value.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Gets or sets audit metadata for the request.
    /// </summary>
    public AuditContext? Audit { get; init; }
    /// <summary>
    /// Gets or sets the expiry value.
    /// </summary>
    public TimeSpan? Expiry { get; init; }
    /// <summary>
    /// Gets or sets the metadata value.
    /// </summary>
    public string? Metadata { get; init; }
}





