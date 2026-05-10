namespace Ashlar.Identity.Notifications;

public sealed class SecurityNotificationResult
{
    public required bool Succeeded { get; init; }
    public bool Suppressed { get; init; }
    public string? FailureReason { get; init; }

    public static SecurityNotificationResult Success() => new() { Succeeded = true };
    public static SecurityNotificationResult SuppressedResult() => new() { Succeeded = true, Suppressed = true };
    public static SecurityNotificationResult Failure(string reason) => new() { Succeeded = false, FailureReason = reason };
}
