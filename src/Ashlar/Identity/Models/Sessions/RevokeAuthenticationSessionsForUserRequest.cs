namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Request parameters for destructive bulk authentication-session revocation.
/// </summary>
/// <param name="Audit">Audit metadata describing who requested the destructive revocation.</param>
/// <param name="Tenant">Scope to revoke within. Use <see cref="TenantContext.Global" /> to revoke only global sessions.</param>
/// <param name="Reason">Optional provider-neutral, display-safe reason for <paramref name="Audit" /> events and notifications. Do not include secrets, tokens, or credentials.</param>
/// <param name="IncludeAllTenants">Whether to revoke sessions for the user across all scopes. Cannot be combined with <paramref name="Tenant" />.</param>
/// <param name="AuditTenantId">Optional scope attribution for emitted security events when it differs from the mutation scope.</param>
public sealed record RevokeAuthenticationSessionsForUserRequest(
    Auditing.AuditContext Audit,
    TenantContext? Tenant,
    string? Reason = null,
    bool IncludeAllTenants = false,
    Guid? AuditTenantId = null)
{
    /// <summary>
    /// Throws when required metadata is missing or revocation scope is ambiguous.
    /// </summary>
    public void ThrowIfInvalid()
    {
        ArgumentNullException.ThrowIfNull(Audit);
        AdministrationScopeValidation.ThrowIfInvalidScope(Tenant, IncludeAllTenants);
    }
}
