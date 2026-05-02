namespace Ashlar.Auditing;

/// <summary>
/// Receives structured Ashlar security events.
/// </summary>
public interface ISecurityEventSink
{
    Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default);
}
