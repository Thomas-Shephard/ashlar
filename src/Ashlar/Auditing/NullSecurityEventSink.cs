namespace Ashlar.Auditing;

/// <summary>
/// Default no-op security event sink.
/// </summary>
public sealed class NullSecurityEventSink : ISecurityEventSink
{
    /// <summary>
    /// Accepts a security event without persisting or forwarding it.
    /// </summary>
    /// <param name="securityEvent">Security event that would otherwise be recorded.</param>
    /// <param name="cancellationToken">A token observed before completing the no-op task.</param>
    /// <returns>A completed task.</returns>
    public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        return Task.CompletedTask;
    }
}
