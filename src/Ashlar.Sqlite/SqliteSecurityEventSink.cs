using System.Text.Json;
using System.Threading.Channels;
using Ashlar.Auditing;
using Ashlar.Identity.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Sqlite;

/// <summary>
/// A SQLite-backed security event sink that persists audit events to the ashlar_security_events table.
/// </summary>
internal sealed class SqliteSecurityEventSink : ISecurityEventSink, IUserSecurityEventSummaryRepository, IAsyncDisposable
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

    private const string IdParameter = "$id";
    private const string EventTypeParameter = "$eventType";
    private const string OccurredAtParameter = "$occurredAt";
    private const string UserIdParameter = "$userId";
    private const string TenantIdParameter = "$tenantId";
    private const string ActorUserIdParameter = "$actorUserId";
    private const string SessionIdParameter = "$sessionId";
    private const string ProviderTypeParameter = "$providerType";
    private const string ProviderNameParameter = "$providerName";
    private const string IpAddressParameter = "$ipAddress";
    private const string UserAgentParameter = "$userAgent";
    private const string CorrelationIdParameter = "$correlationId";
    private const string OutcomeParameter = "$outcome";
    private const string FailureReasonParameter = "$failureReason";
    private const string PropertiesParameter = "$properties";
    private const string SinceParameter = "$since";

    private readonly SqliteConnectionFactory _connectionFactory;
    private readonly ILogger<SqliteSecurityEventSink> _logger;
    private readonly Channel<AshlarSecurityEvent> _channel;
    private readonly Task _backgroundTask;

    public SqliteSecurityEventSink(SqliteConnectionFactory connectionFactory, ILogger<SqliteSecurityEventSink>? logger = null)
    {
        _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        _logger = logger ?? NullLogger<SqliteSecurityEventSink>.Instance;
        _channel = Channel.CreateUnbounded<AshlarSecurityEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

        _backgroundTask = Task.Run(ProcessChannelAsync);
    }

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
                AuthenticationProviderKey.GetTypeValueOrNull(securityEvent.Provider),
                GetProviderName(securityEvent.Provider),
                null);
        }

        return Task.CompletedTask;
    }

    public async Task<int> CountSecurityEventsForUserAsync(Guid userId, DateTimeOffset since, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT COUNT(*)
            FROM ashlar_security_events
            WHERE user_id = $userId AND occurred_at >= $since;
            """;

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.AddGuidParameter(UserIdParameter, userId);
        command.AddDateTimeOffsetParameter(SinceParameter, since);

        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture);
    }

    public async ValueTask DisposeAsync()
    {
        _channel.Writer.TryComplete();
        await _backgroundTask.ConfigureAwait(false);
    }

    private async Task ProcessChannelAsync()
    {
        await foreach (var securityEvent in _channel.Reader.ReadAllAsync())
        {
            try
            {
                await InsertEventAsync(securityEvent, CancellationToken.None);
            }
            catch (Exception exception)
            {
                SecurityEventPersistenceFailed(
                    _logger,
                    securityEvent.EventType,
                    securityEvent.UserId,
                    securityEvent.SessionId,
                    AuthenticationProviderKey.GetTypeValueOrNull(securityEvent.Provider),
                    GetProviderName(securityEvent.Provider),
                    exception);
            }
        }
    }

    private async Task InsertEventAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO ashlar_security_events (
                id, event_type, occurred_at, user_id, tenant_id, actor_user_id, session_id,
                provider_type, provider_name, ip_address, user_agent,
                correlation_id, outcome, failure_reason, properties
            ) VALUES (
                $id, $eventType, $occurredAt, $userId, $tenantId, $actorUserId, $sessionId,
                $providerType, $providerName, $ipAddress, $userAgent,
                $correlationId, $outcome, $failureReason, $properties
            );
            """;

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.AddGuidParameter(IdParameter, securityEvent.Id);
        command.AddParameter(EventTypeParameter, securityEvent.EventType);
        command.AddDateTimeOffsetParameter(OccurredAtParameter, securityEvent.OccurredAt);
        command.AddNullableGuidParameter(UserIdParameter, securityEvent.UserId);
        command.AddNullableGuidParameter(TenantIdParameter, securityEvent.TenantId);
        command.AddNullableGuidParameter(ActorUserIdParameter, securityEvent.ActorUserId);
        command.AddNullableGuidParameter(SessionIdParameter, securityEvent.SessionId);
        command.AddParameter(ProviderTypeParameter, AuthenticationProviderKey.GetTypeValueOrNull(securityEvent.Provider));
        command.AddParameter(ProviderNameParameter, GetProviderName(securityEvent.Provider));
        command.AddParameter(IpAddressParameter, securityEvent.IpAddress);
        command.AddParameter(UserAgentParameter, securityEvent.UserAgent);
        command.AddParameter(CorrelationIdParameter, securityEvent.CorrelationId);
        command.AddParameter(OutcomeParameter, securityEvent.Outcome);
        command.AddParameter(FailureReasonParameter, securityEvent.FailureReason);
        command.AddParameter(PropertiesParameter, securityEvent.Properties != null ? JsonSerializer.Serialize(securityEvent.Properties) : null);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string? GetProviderName(AuthenticationProviderKey? provider)
    {
        return provider?.Name;
    }
}
