using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Identity.Models.Bootstrap;

/// <summary>
/// Configures first-admin bootstrap.
/// </summary>
public sealed class BootstrapOptions
{
    /// <summary>
    /// Gets or sets the operator-controlled setup secret required to authorize first-admin bootstrap.
    /// </summary>
    public string? SetupSecret { get; set; }

    /// <summary>
    /// Gets or sets the grants assigned to the first administrator after setup authorization succeeds.
    /// </summary>
    public List<BootstrapGrantTemplate> Grants { get; set; } = [];

    /// <summary>
    /// Gets or sets the source-based rate limit for first-admin bootstrap attempts.
    /// </summary>
    public RateLimitRule AttemptRateLimit { get; set; } = new() { PermitLimit = 5, Window = TimeSpan.FromMinutes(15) };

    /// <summary>
    /// Gets or sets whether bootstrap request audit events may include the requested email address.
    /// </summary>
    public bool StoreEmailInAudit { get; set; } = true;

    /// <summary>
    /// Validates bootstrap options.
    /// </summary>
    /// <param name="options">The options to validate.</param>
    /// <returns><see langword="true" /> when options are valid.</returns>
    public static bool Validate(BootstrapOptions? options)
    {
        return options is { Grants: not null, AttemptRateLimit: not null }
            && AuthenticationRateLimitRuleValidator.IsValid(options.AttemptRateLimit)
            && options.Grants.All(grant =>
                grant is not null
                && string.IsNullOrWhiteSpace(grant.Role) != string.IsNullOrWhiteSpace(grant.Permission)
                && string.IsNullOrWhiteSpace(grant.ScopeType) == string.IsNullOrWhiteSpace(grant.ScopeId));
    }
}

/// <summary>
/// Describes a grant to assign to the first administrator during bootstrap.
/// </summary>
public sealed class BootstrapGrantTemplate
{
    /// <summary>
    /// Gets or sets the role to assign. Mutually exclusive with <see cref="Permission" />.
    /// </summary>
    public string? Role { get; set; }
    /// <summary>
    /// Gets or sets the permission to assign. Mutually exclusive with <see cref="Role" />.
    /// </summary>
    public string? Permission { get; set; }
    /// <summary>
    /// Gets or sets the optional scope type. Must be supplied together with <see cref="ScopeId" />.
    /// </summary>
    public string? ScopeType { get; set; }
    /// <summary>
    /// Gets or sets the optional scope identifier. Must be supplied together with <see cref="ScopeType" />.
    /// </summary>
    public string? ScopeId { get; set; }
    /// <summary>
    /// Gets or sets the tenant boundary for the grant.
    /// </summary>
    public Guid? TenantId { get; set; }
}
