namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents security event webhook outbox option values surfaced by diagnostics.
/// </summary>
/// <param name="MaxAttempts">The max attempts value.</param>
/// <param name="PollingInterval">The polling interval value.</param>
/// <param name="BatchSize">The batch size value.</param>
public sealed record SecurityEventWebhookOutboxDiagnosticOptions(
    int MaxAttempts,
    TimeSpan PollingInterval,
    int BatchSize);
