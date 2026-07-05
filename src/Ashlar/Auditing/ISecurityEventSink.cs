namespace Ashlar.Auditing;

/// <summary>
/// Receives structured Ashlar security events.
/// </summary>
public interface ISecurityEventSink
{
    /// <summary>
    /// Records a security event.
    /// </summary>
    /// <param name="securityEvent">The provider-neutral security event to record.</param>
    /// <param name="cancellationToken">A token that can cancel event recording.</param>
    /// <returns>
    /// A task that completes after durable persistence when a provider-backed persistent sink is configured, and after
    /// any best-effort application forwarding has been attempted.
    /// </returns>
    Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default);
}
