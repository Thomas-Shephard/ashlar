using System.Text.Json;
using System.Threading.Channels;
using Ashlar.Auditing;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;

namespace Ashlar.Postgres;

/// <summary>
/// A PostgreSQL-backed security event sink that persists audit events to the ashlar_security_events table.
/// </summary>
public sealed class PostgresSecurityEventSink : ISecurityEventSink, IAsyncDisposable
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

    private readonly NpgsqlDataSource _dataSource;
    private readonly ILogger<PostgresSecurityEventSink> _logger;
    private readonly Channel<AshlarSecurityEvent> _channel;
    private readonly Task _backgroundTask;

    /// <summary>
    /// Initializes a new instance of the postgres security event sink class.
    /// </summary>
    /// <param name="dataSource">The data source value.</param>
    /// <param name="logger">The logger value.</param>
    public PostgresSecurityEventSink(NpgsqlDataSource dataSource, ILogger<PostgresSecurityEventSink>? logger = null)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
        _logger = logger ?? NullLogger<PostgresSecurityEventSink>.Instance;
        _channel = Channel.CreateUnbounded<AshlarSecurityEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

        _backgroundTask = Task.Run(ProcessChannelAsync);
    }

    /// <summary>
    /// Records a security event for asynchronous persistence.
    /// </summary>
    /// <param name="securityEvent">The security event.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous record operation.</returns>
    public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if (!_channel.Writer.TryWrite(securityEvent))
        {
            SecurityEventQueueFailed(
                _logger,
                securityEvent.EventType,
                securityEvent.UserId,
                securityEvent.SessionId,
                Ashlar.Identity.Models.AuthenticationProviderKey.GetTypeValueOrNull(securityEvent.Provider),
                GetProviderName(securityEvent.Provider),
                null);
        }
        return Task.CompletedTask;
    }

    private async Task ProcessChannelAsync()
    {
        const string sql = """
            INSERT INTO ashlar_security_events (
                id, event_type, occurred_at, user_id, session_id,
                provider_type, provider_name, ip_address, user_agent,
                correlation_id, outcome, failure_reason, properties
            ) VALUES (
                @Id, @EventType, @OccurredAt, @UserId, @SessionId,
                @ProviderType, @ProviderName, @IpAddress, @UserAgent,
                @CorrelationId, @Outcome, @FailureReason, @Properties::jsonb
            )
            """;

        await foreach (var securityEvent in _channel.Reader.ReadAllAsync())
        {
            try
            {
                var parameters = new
                {
                    securityEvent.Id,
                    securityEvent.EventType,
                    securityEvent.OccurredAt,
                    securityEvent.UserId,
                    securityEvent.SessionId,
                    ProviderType = Ashlar.Identity.Models.AuthenticationProviderKey.GetTypeValueOrNull(securityEvent.Provider),
                    ProviderName = GetProviderName(securityEvent.Provider),
                    securityEvent.IpAddress,
                    securityEvent.UserAgent,
                    securityEvent.CorrelationId,
                    securityEvent.Outcome,
                    securityEvent.FailureReason,
                    Properties = securityEvent.Properties != null ? JsonSerializer.Serialize(securityEvent.Properties) : null
                };

                await using var connection = await _dataSource.OpenConnectionAsync();
                var command = new CommandDefinition(sql, parameters);
                await connection.ExecuteAsync(command);
            }
            catch (Exception exception)
            {
                SecurityEventPersistenceFailed(
                    _logger,
                    securityEvent.EventType,
                    securityEvent.UserId,
                    securityEvent.SessionId,
                    Ashlar.Identity.Models.AuthenticationProviderKey.GetTypeValueOrNull(securityEvent.Provider),
                    GetProviderName(securityEvent.Provider),
                    exception);
            }
        }
    }

    private static string? GetProviderName(Ashlar.Identity.Models.AuthenticationProviderKey? provider)
    {
        return provider?.Name;
    }

    /// <summary>
    /// Performs the dispose <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    public async ValueTask DisposeAsync()
    {
        _channel.Writer.TryComplete();
        await _backgroundTask.ConfigureAwait(false);
    }
}
