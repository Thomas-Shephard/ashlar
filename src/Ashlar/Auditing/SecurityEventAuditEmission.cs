namespace Ashlar.Auditing;

/// <summary>
/// Provides shared fail-open emission for audit events that follow a committed operation.
/// </summary>
public static class SecurityEventAuditEmission
{
    /// <summary>
    /// Records a security event for a completed operation without allowing audit sink failures to change the operation result.
    /// </summary>
    /// <param name="sink">Sink that receives the event.</param>
    /// <param name="timeProvider">Clock used for the event timestamp.</param>
    /// <param name="eventType">Security event type describing the completed operation.</param>
    /// <param name="audit">Required audit context for the operator or calling workflow.</param>
    /// <param name="properties">Non-secret event properties.</param>
    /// <param name="cancellationToken">A token that can cancel event recording.</param>
    /// <returns>A task representing audit emission.</returns>
    public static async Task RecordCompletedOperationAsync(
        ISecurityEventSink sink,
        TimeProvider timeProvider,
        string eventType,
        AuditContext audit,
        IReadOnlyDictionary<string, string> properties,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(properties);

        try
        {
            await sink.RecordAsync(new AshlarSecurityEvent
            {
                Id = Guid.NewGuid(),
                EventType = eventType,
                OccurredAt = timeProvider.GetUtcNow(),
                ActorUserId = audit.ActorUserId,
                IpAddress = audit.IpAddress,
                UserAgent = audit.UserAgent,
                CorrelationId = audit.CorrelationId,
                Outcome = SecurityEventOutcomes.Success,
                Properties = properties
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Audit emission happens after the protected operation has completed and is intentionally fail-open.
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Audit emission happens after the protected operation has completed and is intentionally fail-open.
        }
    }
}
