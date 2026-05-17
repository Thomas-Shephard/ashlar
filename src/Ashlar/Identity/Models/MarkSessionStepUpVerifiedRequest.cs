using Ashlar.Auditing;

namespace Ashlar.Identity.Models;

/// <summary>
/// Request data used to mark an existing active session as recently step-up verified.
/// </summary>
public sealed record MarkSessionStepUpVerifiedRequest
{
    /// <summary>
    /// Gets or initializes the session id to update.
    /// </summary>
    public required Guid SessionId { get; init; }
    /// <summary>
    /// Gets or initializes the provider that completed additional verification.
    /// </summary>
    public required AuthenticationProviderKey VerifiedProvider { get; init; }
    /// <summary>
    /// Gets or initializes the verified factor family.
    /// </summary>
    public required string VerifiedFactor { get; init; }
    /// <summary>
    /// Gets or initializes the tenant context associated with the update.
    /// </summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>
    /// Gets or initializes request audit metadata.
    /// </summary>
    public AuditContext? Audit { get; init; }
}
