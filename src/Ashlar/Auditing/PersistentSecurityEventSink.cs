using Microsoft.Extensions.Logging;

namespace Ashlar.Auditing;

/// <summary>
/// Provides durable persistence for security event sinks.
/// </summary>
/// <param name="logger">Logger used when persistence fails.</param>
/// <remarks>
/// Initializes a new persistent security event sink.
/// </remarks>
public abstract class PersistentSecurityEventSink(ILogger logger) : IPersistentSecurityEventSink
{
    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> SecurityEventPersistenceFailed =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1000, nameof(SecurityEventPersistenceFailed)),
            "Security event persistence failed. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private readonly ILogger _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    /// <inheritdoc />
    public async Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        try
        {
            await PersistAsync(securityEvent, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            LogPersistenceFailure(securityEvent, exception);
            throw;
        }
    }

    /// <summary>
    /// Persists a security event.
    /// </summary>
    /// <param name="securityEvent">The security event.</param>
    /// <param name="cancellationToken">A token that can cancel persistence.</param>
    /// <returns>A task that completes after the event has been written to durable audit storage.</returns>
    protected abstract Task PersistAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken);

    private void LogPersistenceFailure(AshlarSecurityEvent securityEvent, Exception exception)
    {
        SecurityEventPersistenceFailed(
            _logger,
            securityEvent.EventType,
            securityEvent.UserId,
            securityEvent.SessionId,
            AuthenticationProviderKey.GetStorageTypeValue(securityEvent.Provider),
            securityEvent.Provider?.Name,
            exception);
    }
}
