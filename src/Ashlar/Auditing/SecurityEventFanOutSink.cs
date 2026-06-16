using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Auditing;

/// <summary>
/// Records security events to durable storage and notifies registered application handlers.
/// </summary>
public sealed class SecurityEventFanOutSink : ISecurityEventSink
{
    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> PersistentSecurityEventSinkFailed =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1000, nameof(PersistentSecurityEventSinkFailed)),
            "Persistent security event sink failed. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> SecurityEventHandlerFailed =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1001, nameof(SecurityEventHandlerFailed)),
            "Security event handler failed. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private readonly IPersistentSecurityEventSink? _persistentSink;
    private readonly IReadOnlyList<ISecurityEventHandler> _handlers;
    private readonly ILogger<SecurityEventFanOutSink> _logger;

    /// <summary>
    /// Initializes a sink that persists events and invokes registered handlers.
    /// </summary>
    /// <param name="persistentSink">The optional durable audit sink.</param>
    /// <param name="handlers">The registered security event handlers.</param>
    /// <param name="logger">Logger used when persistence or handler delivery fails.</param>
    public SecurityEventFanOutSink(
        IPersistentSecurityEventSink? persistentSink = null,
        IEnumerable<ISecurityEventHandler>? handlers = null,
        ILogger<SecurityEventFanOutSink>? logger = null)
    {
        _persistentSink = persistentSink;
        _handlers = handlers?.ToArray() ?? [];
        _logger = logger ?? NullLogger<SecurityEventFanOutSink>.Instance;
    }

    /// <inheritdoc />
    public async Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        cancellationToken.ThrowIfCancellationRequested();

        if (_persistentSink is not null)
        {
            try
            {
                await _persistentSink.RecordAsync(securityEvent, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                LogPersistentSinkFailure(securityEvent, exception);
            }
        }

        foreach (var handler in _handlers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await handler.HandleAsync(securityEvent, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                LogHandlerFailure(securityEvent, exception);
            }
        }
    }

    private void LogPersistentSinkFailure(AshlarSecurityEvent securityEvent, Exception exception)
    {
        PersistentSecurityEventSinkFailed(
            _logger,
            securityEvent.EventType,
            securityEvent.UserId,
            securityEvent.SessionId,
            AuthenticationProviderKey.GetStorageTypeValue(securityEvent.Provider),
            GetProviderName(securityEvent.Provider),
            exception);
    }

    private void LogHandlerFailure(AshlarSecurityEvent securityEvent, Exception exception)
    {
        SecurityEventHandlerFailed(
            _logger,
            securityEvent.EventType,
            securityEvent.UserId,
            securityEvent.SessionId,
            AuthenticationProviderKey.GetStorageTypeValue(securityEvent.Provider),
            GetProviderName(securityEvent.Provider),
            exception);
    }

    private static string? GetProviderName(AuthenticationProviderKey? provider)
    {
        return provider?.Name;
    }
}
