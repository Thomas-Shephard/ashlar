using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Request data used to mark an existing active session as recently step-up verified.
/// </summary>
public sealed record MarkSessionStepUpVerifiedRequest
{
    /// <summary>
    /// Application session to mark as freshly step-up verified.
    /// </summary>
    public required Guid SessionId { get; init; }
    /// <summary>
    /// Provider that satisfied the additional verification challenge.
    /// </summary>
    public required AuthenticationProviderKey VerifiedProvider { get; init; }
    /// <summary>
    /// Provider-neutral factor family that satisfied step-up verification.
    /// </summary>
    public required string VerifiedFactor { get; init; }
    /// <summary>
    /// Tenant scope used to validate the session owner and audit context. Use <see cref="TenantContext.Global" /> for global users; this API does not use <see langword="null" /> to skip ownership checks.
    /// </summary>
    public TenantContext? Tenant { get; init; }
    /// <summary>
    /// Audit metadata recorded with the step-up verification update.
    /// </summary>
    public AuditContext? Audit { get; init; }
}
