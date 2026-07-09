using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Auditing;

/// <summary>
/// Records security events to durable storage, runs required durable continuations, and notifies best-effort handlers.
/// </summary>
/// <remarks>
/// When transaction support is configured, persistent audit and durable fan-out handlers commit or roll back
/// together. Best-effort handlers run after the durable transaction commits.
/// </remarks>
public sealed class SecurityEventFanOutSink : ISecurityEventSink
{
    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> SecurityEventHandlerFailed =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1001, nameof(SecurityEventHandlerFailed)),
            "Security event handler failed. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private readonly IPersistentSecurityEventSink? _persistentSink;
    private readonly IDurableSecurityEventFanOutHandler[] _durableHandlers;
    private readonly ISecurityEventHandler[] _handlers;
    private readonly IAshlarTransactionProvider? _transactionProvider;
    private readonly ILogger<SecurityEventFanOutSink> _logger;

    /// <summary>
    /// Initializes a sink that persists events and invokes registered handlers.
    /// </summary>
    /// <param name="persistentSink">The optional durable audit sink.</param>
    /// <param name="handlers">The registered security event handlers.</param>
    /// <param name="logger">Logger used when persistence or handler delivery fails.</param>
    /// <param name="transactionProvider">Optional transaction provider used to commit durable audit and fan-out atomically.</param>
    /// <param name="durableHandlers">Required transaction-bound security event continuations.</param>
    public SecurityEventFanOutSink(
        IPersistentSecurityEventSink? persistentSink = null,
        IEnumerable<ISecurityEventHandler>? handlers = null,
        ILogger<SecurityEventFanOutSink>? logger = null,
        IAshlarTransactionProvider? transactionProvider = null,
        IEnumerable<IDurableSecurityEventFanOutHandler>? durableHandlers = null)
    {
        _persistentSink = persistentSink;
        _durableHandlers = durableHandlers?.ToArray() ?? [];
        _handlers = handlers?.ToArray() ?? [];
        _transactionProvider = transactionProvider;
        _logger = logger ?? NullLogger<SecurityEventFanOutSink>.Instance;
    }

    /// <inheritdoc />
    public async Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        cancellationToken.ThrowIfCancellationRequested();

        if (_transactionProvider is not null)
        {
            await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            var commitStarted = false;
            try
            {
                await RecordDurableAsync(securityEvent, cancellationToken).ConfigureAwait(false);
                if (_handlers.Length != 0)
                {
                    transaction.OnCommitted(ct => RunHandlersAsync(securityEvent, ct));
                }

                commitStarted = true;
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                if (!commitStarted)
                {
                    await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
                }

                throw;
            }

        }
        else
        {
            await RecordDurableAsync(securityEvent, cancellationToken).ConfigureAwait(false);

            if (_handlers.Length != 0)
            {
                await RunHandlersAsync(securityEvent, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task RecordDurableAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        if (_persistentSink is not null)
        {
            await _persistentSink.RecordAsync(securityEvent, cancellationToken).ConfigureAwait(false);
        }

        foreach (var durableHandler in _durableHandlers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await durableHandler.HandleAsync(securityEvent, cancellationToken).ConfigureAwait(false);
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
}
