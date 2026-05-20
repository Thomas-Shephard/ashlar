namespace Ashlar.Auditing;

/// <summary>
/// Default no-op security event sink.
/// </summary>
public sealed class NullSecurityEventSink : ISecurityEventSink
{
    /// <summary>
    /// Performs the record <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="securityEvent">The security event value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        return Task.CompletedTask;
    }
}


