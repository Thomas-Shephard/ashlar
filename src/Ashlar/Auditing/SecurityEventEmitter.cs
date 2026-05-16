using Ashlar.Identity.Models;
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
                SessionId = descriptor.SessionId,
                Provider = descriptor.Provider,
                IpAddress = descriptor.Context?.IpAddress ?? descriptor.IpAddress,
                UserAgent = descriptor.Context?.UserAgent ?? descriptor.UserAgent,
                CorrelationId = descriptor.Context?.CorrelationId ?? descriptor.CorrelationId,
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
                AuthenticationProviderKey.GetTypeValueOrNull(descriptor.Provider),
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
                AuthenticationProviderKey.GetTypeValueOrNull(descriptor.Provider),
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
    /// Gets or sets the event type value.
    /// </summary>
    public required string EventType { get; init; }
    /// <summary>
    /// Gets or sets the outcome value.
    /// </summary>
    public required string Outcome { get; init; }
    /// <summary>
    /// Gets or sets the user id value.
    /// </summary>
    public Guid? UserId { get; init; }
    /// <summary>
    /// Gets or sets the session id value.
    /// </summary>
    public Guid? SessionId { get; init; }
    /// <summary>
    /// Gets or sets the provider value.
    /// </summary>
    public AuthenticationProviderKey? Provider { get; init; }
    /// <summary>
    /// Gets or sets the context value.
    /// </summary>
    public AuthenticationContext? Context { get; init; }
    /// <summary>
    /// Gets or sets the ip address value.
    /// </summary>
    public string? IpAddress { get; init; }
    /// <summary>
    /// Gets or sets the user agent value.
    /// </summary>
    public string? UserAgent { get; init; }
    /// <summary>
    /// Gets or sets the correlation id value.
    /// </summary>
    public string? CorrelationId { get; init; }
    /// <summary>
    /// Gets or sets the failure reason value.
    /// </summary>
    public string? FailureReason { get; init; }
    /// <summary>
    /// Gets or sets the properties value.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Properties { get; init; }
}
