using System.Text.Json;

namespace Ashlar.Auditing;

/// <summary>
/// Represents a security event projected into provider-neutral storage values.
/// </summary>
/// <param name="Id">The event identifier.</param>
/// <param name="EventType">The event type.</param>
/// <param name="OccurredAt">The occurrence time.</param>
/// <param name="UserId">The user identifier.</param>
/// <param name="TenantId">The tenant identifier.</param>
/// <param name="ActorUserId">The actor user identifier.</param>
/// <param name="SessionId">The session identifier.</param>
/// <param name="ProviderType">The provider type.</param>
/// <param name="ProviderName">The provider name.</param>
/// <param name="IpAddress">The IP address.</param>
/// <param name="UserAgent">The user agent.</param>
/// <param name="CorrelationId">The correlation identifier.</param>
/// <param name="Outcome">The event outcome.</param>
/// <param name="FailureReason">The failure reason.</param>
/// <param name="PropertiesJson">The serialized event properties.</param>
public sealed record SecurityEventStorageRecord(
    Guid Id,
    string EventType,
    DateTimeOffset OccurredAt,
    Guid? UserId,
    Guid? TenantId,
    Guid? ActorUserId,
    Guid? SessionId,
    string? ProviderType,
    string? ProviderName,
    string? IpAddress,
    string? UserAgent,
    string? CorrelationId,
    string? Outcome,
    string? FailureReason,
    string? PropertiesJson)
{
    /// <summary>
    /// Creates a storage record from a security event.
    /// </summary>
    /// <param name="securityEvent">The security event.</param>
    /// <returns>The storage record.</returns>
    public static SecurityEventStorageRecord From(AshlarSecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        return new SecurityEventStorageRecord(
            securityEvent.Id,
            securityEvent.EventType,
            securityEvent.OccurredAt,
            securityEvent.UserId,
            securityEvent.TenantId,
            securityEvent.ActorUserId,
            securityEvent.SessionId,
            AuthenticationProviderKey.GetTypeValueOrNull(securityEvent.Provider),
            securityEvent.Provider?.Name,
            securityEvent.IpAddress,
            securityEvent.UserAgent,
            securityEvent.CorrelationId,
            securityEvent.Outcome,
            securityEvent.FailureReason,
            securityEvent.Properties != null ? JsonSerializer.Serialize(securityEvent.Properties) : null);
    }
}
