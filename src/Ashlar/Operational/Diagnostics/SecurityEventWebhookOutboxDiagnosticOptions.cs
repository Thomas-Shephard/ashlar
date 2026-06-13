namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Describes security event webhook outbox dispatcher settings surfaced by diagnostics.
/// </summary>
/// <param name="MaxAttempts">Maximum delivery attempts before a webhook delivery is marked failed.</param>
/// <param name="PollingInterval">Dispatcher polling interval for pending webhook deliveries.</param>
/// <param name="BatchSize">Maximum webhook deliveries claimed by one dispatcher batch.</param>
public sealed record SecurityEventWebhookOutboxDiagnosticOptions(
    int MaxAttempts,
    TimeSpan PollingInterval,
    int BatchSize);
