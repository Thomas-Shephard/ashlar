namespace Ashlar.Identity.Abstractions.Tenancy;

/// <summary>
/// Defines the contract for itenant user operations.
/// </summary>
public interface ITenantUser : IUser
{
    /// <summary>
    /// Gets the tenant id value.
    /// </summary>
    Guid? TenantId { get; }
}
