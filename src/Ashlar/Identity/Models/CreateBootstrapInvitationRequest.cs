namespace Ashlar.Identity.Models;

public sealed class CreateBootstrapInvitationRequest
{
    public required string Email { get; init; }
    public string? UserName { get; init; }
    public Guid? TenantId { get; init; }
    public TimeSpan? Expiry { get; init; }
    public string? Metadata { get; init; }
}
