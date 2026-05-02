namespace Ashlar.Auditing;

/// <summary>
/// Default no-op security event sink.
/// </summary>
public sealed class NullSecurityEventSink : ISecurityEventSink
{
    public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        return Task.CompletedTask;
    }
}
