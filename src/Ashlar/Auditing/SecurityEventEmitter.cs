using Ashlar.Identity.Models;

namespace Ashlar.Auditing;

internal sealed class SecurityEventEmitter(ISecurityEventSink? sink, TimeProvider? timeProvider)
{
    private readonly ISecurityEventSink _sink = sink ?? NullSecurityEventSinkInstance.Value;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

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
            // TODO: Log audit sink cancellation once Ashlar has a core logging convention.
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Ashlar currently fails open for audit emission to ensure service availability.
            // In highly regulated environments, this may need to be configurable to fail-closed.
            // TODO: Log audit sink failures once Ashlar has a core logging convention.
        }
    }

    private static class NullSecurityEventSinkInstance
    {
        internal static readonly NullSecurityEventSink Value = new();
    }
}

internal sealed record SecurityEventDescriptor
{
    public required string EventType { get; init; }
    public required string Outcome { get; init; }
    public Guid? UserId { get; init; }
    public Guid? SessionId { get; init; }
    public AuthenticationProviderKey? Provider { get; init; }
    public AuthenticationContext? Context { get; init; }
    public string? IpAddress { get; init; }
    public string? UserAgent { get; init; }
    public string? CorrelationId { get; init; }
    public string? FailureReason { get; init; }
    public IReadOnlyDictionary<string, string>? Properties { get; init; }
}
