namespace Ashlar.Identity.Models;

public sealed class InvitationAcceptanceResult
{
    public required bool Succeeded { get; init; }
    public Guid? UserId { get; init; }
    public string? FailureReason { get; init; }

    public static InvitationAcceptanceResult Success(Guid userId) => new() { Succeeded = true, UserId = userId };
    public static InvitationAcceptanceResult Failure(string reason) => new() { Succeeded = false, FailureReason = reason };
}
