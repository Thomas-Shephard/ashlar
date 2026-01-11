namespace Ashlar.Identity.Abstractions;

public interface ITenantUser : IUser
{
    Guid? TenantId { get; }
}
