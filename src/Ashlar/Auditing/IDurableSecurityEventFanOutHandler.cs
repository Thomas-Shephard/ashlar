namespace Ashlar.Auditing;

/// <summary>
/// Handles required security event continuations inside the active protected mutation transaction.
/// </summary>
/// <remarks>
/// Implementations are for durable work that must commit or roll back with the security event audit record.
/// Failures are propagated to the caller so the protected operation can roll back.
/// </remarks>
public interface IDurableSecurityEventFanOutHandler
{
    /// <summary>
    /// Handles a security event before best-effort post-commit handlers are scheduled.
    /// </summary>
    /// <param name="securityEvent">The provider-neutral security event to handle.</param>
    /// <param name="cancellationToken">A token that can cancel event handling.</param>
    /// <returns>A task that completes after required durable work has finished.</returns>
    Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default);
}
