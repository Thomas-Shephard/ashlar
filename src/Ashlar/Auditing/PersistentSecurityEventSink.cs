using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace Ashlar.Auditing;

/// <summary>
/// Provides asynchronous channel-based persistence for security event sinks.
/// </summary>
public abstract class PersistentSecurityEventSink : IPersistentSecurityEventSink, IAsyncDisposable
{
    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> SecurityEventQueueFailed =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1000, nameof(SecurityEventQueueFailed)),
            "Security event could not be queued for persistence. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> SecurityEventPersistenceFailed =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1001, nameof(SecurityEventPersistenceFailed)),
            "Security event persistence failed. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private readonly ILogger _logger;
    private readonly Channel<AshlarSecurityEvent> _channel;
    private readonly Task _backgroundTask;

    /// <summary>
    /// Initializes a new persistent security event sink.
    /// </summary>
    /// <param name="logger">Logger used when queueing or persistence fails.</param>
    protected PersistentSecurityEventSink(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _channel = Channel.CreateUnbounded<AshlarSecurityEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

        _backgroundTask = Task.Run(ProcessChannelAsync);
    }

    /// <inheritdoc />
    public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if (!_channel.Writer.TryWrite(securityEvent))
        {
            LogQueueFailure(securityEvent);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Completes the sink and waits for queued events to drain.
    /// </summary>
    /// <returns>A task that completes after the background persistence loop has drained queued events.</returns>
    public async ValueTask DisposeAsync()
    {
        _channel.Writer.TryComplete();
        await _backgroundTask.ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Persists a security event.
    /// </summary>
    /// <param name="securityEvent">The security event.</param>
    /// <param name="cancellationToken">A token that can cancel persistence.</param>
    /// <returns>A task that completes after the event has been written to durable audit storage.</returns>
    protected abstract Task PersistAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the provider name from a provider key.
    /// </summary>
    /// <param name="provider">The provider key.</param>
    /// <returns>The provider name, or <see langword="null" />.</returns>
    protected static string? GetProviderName(AuthenticationProviderKey? provider)
    {
        return provider?.Name;
    }

    private async Task ProcessChannelAsync()
    {
        await foreach (var securityEvent in _channel.Reader.ReadAllAsync())
        {
            try
            {
                await PersistAsync(securityEvent, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                LogPersistenceFailure(securityEvent, exception);
            }
        }
    }

    private void LogQueueFailure(AshlarSecurityEvent securityEvent)
    {
        SecurityEventQueueFailed(
            _logger,
            securityEvent.EventType,
            securityEvent.UserId,
            securityEvent.SessionId,
            AuthenticationProviderKey.GetTypeValueOrDefault(securityEvent.Provider),
            GetProviderName(securityEvent.Provider),
            null);
    }

    private void LogPersistenceFailure(AshlarSecurityEvent securityEvent, Exception exception)
    {
        SecurityEventPersistenceFailed(
            _logger,
            securityEvent.EventType,
            securityEvent.UserId,
            securityEvent.SessionId,
            AuthenticationProviderKey.GetTypeValueOrDefault(securityEvent.Provider),
            GetProviderName(securityEvent.Provider),
            exception);
    }
}
