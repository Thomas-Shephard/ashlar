namespace Ashlar.Identity.Abstractions.Tenancy;

/// <summary>
/// Describes a user that may belong to a tenant scope.
/// </summary>
public interface ITenantUser : IUser
{
    /// <summary>
    /// Tenant identifier for tenant-scoped users, or <see langword="null" /> for global users. Sessions and tenant-bound security state must use this exact scope.
    /// </summary>
    Guid? TenantId { get; }
}
