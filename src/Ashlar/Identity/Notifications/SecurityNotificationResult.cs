namespace Ashlar.Identity.Notifications;

/// <summary>
/// Provides security notification result behavior.
/// </summary>
public sealed class SecurityNotificationResult
{
    /// <summary>
    /// Gets or sets the succeeded value.
    /// </summary>
    public required bool Succeeded { get; init; }
    /// <summary>
    /// Gets or sets the suppressed value.
    /// </summary>
    public bool Suppressed { get; init; }
    /// <summary>
    /// Gets or sets the failure reason value.
    /// </summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// Executes the success operation.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static SecurityNotificationResult Success() => new() { Succeeded = true };
    /// <summary>
    /// Executes the suppressed result operation.
    /// </summary>
    /// <returns>The operation result.</returns>
    public static SecurityNotificationResult SuppressedResult() => new() { Succeeded = true, Suppressed = true };
    /// <summary>
    /// Executes the failure operation.
    /// </summary>
    /// <param name="reason">The failure reason.</param>
    /// <returns>The operation result.</returns>
    public static SecurityNotificationResult Failure(string reason) => new() { Succeeded = false, FailureReason = reason };
}


