namespace Ashlar.Auditing;

/// <summary>
/// Receives structured Ashlar security events.
/// </summary>
public interface ISecurityEventSink
{
    /// <summary>
    /// Records a security event in durable or application-provided audit storage.
    /// </summary>
    /// <param name="securityEvent">The provider-neutral security event to persist or forward.</param>
    /// <param name="cancellationToken">A token that can cancel event recording.</param>
    /// <returns>A task that completes after the sink has accepted the event for persistence or forwarding.</returns>
    Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default);
}
