using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Auditing;

internal sealed class SecurityEventEmitter(ISecurityEventSink? sink, TimeProvider? timeProvider, ILoggerFactory? loggerFactory = null)
{
    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> SecurityEventEmissionCanceled =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1000, nameof(SecurityEventEmissionCanceled)),
            "Security event emission was canceled by the sink. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, string, Guid?, Guid?, string?, string?, Exception?> SecurityEventEmissionFailed =
        LoggerMessage.Define<string, Guid?, Guid?, string?, string?>(
            LogLevel.Warning,
            new EventId(1001, nameof(SecurityEventEmissionFailed)),
            "Security event emission failed. EventType={EventType} UserId={UserId} SessionId={SessionId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private readonly ISecurityEventSink _sink = sink ?? NullSecurityEventSinkInstance.Value;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly ILogger<SecurityEventEmitter> _logger = loggerFactory?.CreateLogger<SecurityEventEmitter>() ?? NullLogger<SecurityEventEmitter>.Instance;

    public async Task RecordAsync(
        SecurityEventDescriptor descriptor,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await _sink.RecordAsync(new AshlarSecurityEvent
            {
                Id = Guid.NewGuid(),
                EventType = descriptor.EventType,
                OccurredAt = _timeProvider.GetUtcNow(),
                UserId = descriptor.UserId,
                TenantId = descriptor.TenantId ?? descriptor.Context?.TenantId,
                ActorUserId = descriptor.Audit?.ActorUserId ?? descriptor.Context?.UserId,
                SessionId = descriptor.SessionId,
                Provider = descriptor.Provider,
                IpAddress = descriptor.Audit?.IpAddress ?? descriptor.Context?.IpAddress ?? descriptor.IpAddress,
                UserAgent = descriptor.Audit?.UserAgent ?? descriptor.Context?.UserAgent ?? descriptor.UserAgent,
                CorrelationId = descriptor.Audit?.CorrelationId ?? descriptor.Context?.CorrelationId ?? descriptor.CorrelationId,
                Outcome = descriptor.Outcome,
                FailureReason = descriptor.FailureReason,
                Properties = descriptor.Properties
            }, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Ashlar currently fails open for audit emission to ensure service availability.
            SecurityEventEmissionCanceled(
                _logger,
                descriptor.EventType,
                descriptor.UserId,
                descriptor.SessionId,
                AuthenticationProviderKey.GetTypeValueOrDefault(descriptor.Provider),
                GetProviderName(descriptor.Provider),
                null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Ashlar currently fails open for audit emission to ensure service availability.
            // In highly regulated environments, this may need to be configurable to fail-closed.
            SecurityEventEmissionFailed(
                _logger,
                descriptor.EventType,
                descriptor.UserId,
                descriptor.SessionId,
                AuthenticationProviderKey.GetTypeValueOrDefault(descriptor.Provider),
                GetProviderName(descriptor.Provider),
                ex);
        }
    }

    private static string? GetProviderName(AuthenticationProviderKey? provider)
    {
        return provider?.Name;
    }

    private static class NullSecurityEventSinkInstance
    {
        internal static readonly NullSecurityEventSink Value = new();
    }
}

internal sealed record SecurityEventDescriptor
{
    /// <summary>
    /// Security event type to record.
    /// </summary>
    public required string EventType { get; init; }
    /// <summary>
    /// Outcome to record for the event.
    /// </summary>
    public required string Outcome { get; init; }
    /// <summary>
    /// Affected user identifier, when the event is user-scoped.
    /// </summary>
    public Guid? UserId { get; init; }
    /// <summary>
    /// Tenant scope for the event, when available.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Host-supplied audit metadata to merge into the event.
    /// </summary>
    public AuditContext? Audit { get; init; }
    /// <summary>
    /// Affected application session identifier, when available.
    /// </summary>
    public Guid? SessionId { get; init; }
    /// <summary>
    /// Authentication provider associated with the event, when available.
    /// </summary>
    public AuthenticationProviderKey? Provider { get; init; }
    /// <summary>
    /// Authentication context used to fill missing tenant, actor, and request metadata.
    /// </summary>
    public AuthenticationContext? Context { get; init; }
    /// <summary>
    /// Fallback client IP address to use when audit and authentication context metadata omit it.
    /// </summary>
    public string? IpAddress { get; init; }
    /// <summary>
    /// Fallback client user-agent text to use when audit and authentication context metadata omit it.
    /// </summary>
    public string? UserAgent { get; init; }
    /// <summary>
    /// Fallback correlation identifier to use when audit and authentication context metadata omit it.
    /// </summary>
    public string? CorrelationId { get; init; }
    /// <summary>
    /// Provider-neutral failure reason for unsuccessful events.
    /// </summary>
    public string? FailureReason { get; init; }
    /// <summary>
    /// Additional non-secret event properties. Do not include credentials, tokens, hashes, or protected payloads.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Properties { get; init; }
}
