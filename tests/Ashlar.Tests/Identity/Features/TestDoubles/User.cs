namespace Ashlar.Tests.Identity.Features.TestDoubles;

internal sealed class User : ITenantUser
{
    public required Guid Id { get; init; }
    public required string Email { get; set; }
    public string? Name { get; set; }
    public UserAccountState AccountState { get; set; } = UserAccountState.Active;
    public Guid? TenantId { get; set; }
    public DateTimeOffset? EmailVerifiedAt { get; set; }
}
