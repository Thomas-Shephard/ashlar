namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Describes email outbox dispatcher settings surfaced by diagnostics.
/// </summary>
/// <param name="MaxAttempts">Maximum delivery attempts before a message is marked failed.</param>
/// <param name="PollingInterval">Dispatcher polling interval for pending messages.</param>
/// <param name="BatchSize">Maximum messages claimed by one dispatcher batch.</param>
public sealed record EmailOutboxDiagnosticOptions(
    int MaxAttempts,
    TimeSpan PollingInterval,
    int BatchSize);
