using System.Text.Json;
using System.Threading.Channels;
using Ashlar.Auditing;
using Dapper;
using Npgsql;

namespace Ashlar.Postgres;

/// <summary>
/// A PostgreSQL-backed security event sink that persists audit events to the ashlar_security_events table.
/// </summary>
public sealed class PostgresSecurityEventSink : ISecurityEventSink, IAsyncDisposable
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly Channel<AshlarSecurityEvent> _channel;
    private readonly Task _backgroundTask;

    public PostgresSecurityEventSink(NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
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
            // TODO: add logging
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
                    ProviderType = securityEvent.Provider?.Type.Value,
                    ProviderName = securityEvent.Provider?.Name,
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
            catch
            {
                // Swallowing to prevent background task termination
                // TODO: add logging
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _channel.Writer.TryComplete();
        await _backgroundTask.ConfigureAwait(false);
    }
}
