using Ashlar.Auditing;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Represents a request to generate new recovery codes.
/// </summary>
public sealed record RecoveryCodeGenerationRequest
{
    /// <summary>
    /// Gets or sets a value indicating whether existing recovery codes should be revoked before generating new ones.
    /// Defaults to <c><see langword="true" /></c>.
    /// </summary>
    public bool ReplaceExisting { get; init; } = true;

    /// <summary>
    /// Gets or sets the number of codes to generate. If <see langword="null" />, the configured default in <see cref="RecoveryCodeOptions"/> is used.
    /// </summary>
    public int? CodeCount { get; init; }

    /// <summary>
    /// Gets or sets the duration after which the codes expire. If <see langword="null" />, the configured default in <see cref="RecoveryCodeOptions"/> is used.
    /// </summary>
    public TimeSpan? ExpiresAfter { get; init; }

    /// <summary>
    /// Gets the tenant context for recovery-code generation.
    /// </summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>
    /// Gets audit metadata describing who requested recovery-code generation.
    /// </summary>
    public AuditContext? Audit { get; init; }
}


