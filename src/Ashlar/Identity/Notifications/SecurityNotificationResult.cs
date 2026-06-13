namespace Ashlar.Identity.Notifications;

/// <summary>
/// Reports the result of attempting to emit a security notification.
/// </summary>
public sealed class SecurityNotificationResult
{
    /// <summary>
    /// Whether notification processing completed successfully.
    /// </summary>
    public required bool Succeeded { get; init; }
    /// <summary>
    /// Whether delivery was intentionally skipped by suppression rules.
    /// </summary>
    public bool Suppressed { get; init; }
    /// <summary>
    /// Diagnostic failure reason when processing did not succeed. Do not render this value directly to end users.
    /// </summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// Creates a successful notification result.
    /// </summary>
    /// <returns>A result indicating delivery processing succeeded.</returns>
    public static SecurityNotificationResult Success() => new() { Succeeded = true };
    /// <summary>
    /// Creates a result for a notification skipped by suppression rules.
    /// </summary>
    /// <returns>A successful result marked as suppressed.</returns>
    public static SecurityNotificationResult SuppressedResult() => new() { Succeeded = true, Suppressed = true };
    /// <summary>
    /// Creates a failed notification result.
    /// </summary>
    /// <param name="reason">Diagnostic failure reason. Do not render this value directly to end users.</param>
    /// <returns>A result containing the failure reason.</returns>
    public static SecurityNotificationResult Failure(string reason) => new() { Succeeded = false, FailureReason = reason };
}
