namespace Ashlar.Identity.Models;

public sealed class AcceptInvitationRequest
{
    public required string Token { get; init; }
    public string? UserName { get; init; }
}
