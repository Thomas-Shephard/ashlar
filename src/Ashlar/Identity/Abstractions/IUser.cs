namespace Ashlar.Identity.Abstractions;

public interface IUser
{
    Guid Id { get; }
    string Email { get; }
    string? Name { get; }
    bool IsActive { get; }
}