using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Auditing;

/// <summary>
/// Observes Ashlar security events for application reactions.
/// </summary>
/// <remarks>
/// Handlers receive already-created security event instances. They must not mutate the event object and are not
/// durable audit storage.
/// </remarks>
[SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix", Justification = "This is an application security event handler abstraction, not a .NET event delegate.")]
public interface ISecurityEventHandler
{
    /// <summary>
    /// Handles a security event.
    /// </summary>
    /// <param name="securityEvent">The security event value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task that represents the asynchronous handle operation.</returns>
    Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default);
}
