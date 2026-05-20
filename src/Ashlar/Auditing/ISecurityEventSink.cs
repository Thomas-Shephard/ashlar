namespace Ashlar.Auditing;

/// <summary>
/// Receives structured Ashlar security events.
/// </summary>
public interface ISecurityEventSink
{
    /// <summary>
    /// Performs the record <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="securityEvent">The security event value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default);
}


