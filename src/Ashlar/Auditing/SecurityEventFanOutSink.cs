using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Auditing;

/// <summary>
/// Records security events to durable storage and notifies registered best-effort application handlers.
/// </summary>
public sealed class SecurityEventFanOutSink : ISecurityEventSink
{
    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> SecurityEventHandlerFailed =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1001, nameof(SecurityEventHandlerFailed)),
            "Security event handler failed. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> SecurityEventFanOutSchedulingFailed =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1002, nameof(SecurityEventFanOutSchedulingFailed)),
            "Security event fan-out scheduling failed. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private readonly IPersistentSecurityEventSink? _persistentSink;
    private readonly ISecurityEventHandler[] _handlers;
    private readonly IAshlarTransactionProvider? _transactionProvider;
    private readonly ILogger<SecurityEventFanOutSink> _logger;

    /// <summary>
    /// Initializes a sink that persists events and invokes registered handlers.
    /// </summary>
    /// <param name="persistentSink">The optional durable audit sink.</param>
    /// <param name="handlers">The registered security event handlers.</param>
    /// <param name="logger">Logger used when persistence or handler delivery fails.</param>
    /// <param name="transactionProvider">Optional transaction provider used to run best-effort handlers after commit.</param>
    public SecurityEventFanOutSink(
        IPersistentSecurityEventSink? persistentSink = null,
        IEnumerable<ISecurityEventHandler>? handlers = null,
        ILogger<SecurityEventFanOutSink>? logger = null,
        IAshlarTransactionProvider? transactionProvider = null)
    {
        _persistentSink = persistentSink;
        _handlers = handlers?.ToArray() ?? [];
        _transactionProvider = transactionProvider;
        _logger = logger ?? NullLogger<SecurityEventFanOutSink>.Instance;
    }

    /// <inheritdoc />
    public async Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        cancellationToken.ThrowIfCancellationRequested();

        if (_persistentSink is not null)
        {
            await _persistentSink.RecordAsync(securityEvent, cancellationToken).ConfigureAwait(false);
        }

        if (_handlers.Length == 0)
        {
            return;
        }

        if (_transactionProvider is not null)
        {
            try
            {
                await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
                transaction.OnCommitted(ct => RunHandlersAsync(securityEvent, ct));
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                LogFanOutSchedulingFailure(securityEvent, exception);
            }
        }
        else
        {
            await RunHandlersAsync(securityEvent, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task RunHandlersAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken)
    {
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

    private void LogHandlerFailure(AshlarSecurityEvent securityEvent, Exception exception)
    {
        SecurityEventHandlerFailed(
            _logger,
            securityEvent.EventType,
            securityEvent.UserId,
            securityEvent.SessionId,
            AuthenticationProviderKey.GetStorageTypeValue(securityEvent.Provider),
            securityEvent.Provider?.Name,
            exception);
    }

    private void LogFanOutSchedulingFailure(AshlarSecurityEvent securityEvent, Exception exception)
    {
        SecurityEventFanOutSchedulingFailed(
            _logger,
            securityEvent.EventType,
            securityEvent.UserId,
            securityEvent.SessionId,
            AuthenticationProviderKey.GetStorageTypeValue(securityEvent.Provider),
            securityEvent.Provider?.Name,
            exception);
    }
}
