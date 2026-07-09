using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Auditing;

/// <summary>
/// Observes Ashlar security events after durable work has committed.
/// </summary>
/// <remarks>
/// Handlers are best-effort post-commit callbacks. Their failures are logged and do not roll back the protected
/// operation, the audit record, or transaction-bound continuations such as webhook outbox enqueue.
/// </remarks>
[SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix", Justification = "This is an application security event handler abstraction, not a .NET event delegate.")]
public interface ISecurityEventHandler
{
    /// <summary>
    /// Handles a committed security event.
    /// </summary>
    /// <param name="securityEvent">The provider-neutral security event to observe.</param>
    /// <param name="cancellationToken">A token that can cancel event handling.</param>
    /// <returns>A task that completes after the handler has observed the event.</returns>
    Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default);
}
