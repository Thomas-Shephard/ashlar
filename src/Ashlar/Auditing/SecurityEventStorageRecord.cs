using System.Text.Json;

namespace Ashlar.Auditing;

/// <summary>
/// Represents a security event projected into provider-neutral storage values.
/// </summary>
/// <param name="Id">Stable identifier for this recorded audit event.</param>
/// <param name="EventType">Normalized security event type.</param>
/// <param name="OccurredAt">UTC time when the event occurred.</param>
/// <param name="UserId">Affected user identifier, when the event is user-scoped.</param>
/// <param name="TenantId">Tenant scope associated with the event, when available.</param>
/// <param name="ActorUserId">Administrator or actor user identifier, when available.</param>
/// <param name="SessionId">Related application session identifier, when available.</param>
/// <param name="ProviderType">Authentication provider type captured for storage, when available.</param>
/// <param name="ProviderName">Authentication provider name captured for storage, when available.</param>
/// <param name="IpAddress">Client IP address captured for audit. Treat as personal data.</param>
/// <param name="UserAgent">Client user-agent text captured for audit. It may be user supplied.</param>
/// <param name="CorrelationId">Host-defined request or trace correlation identifier, when available.</param>
/// <param name="Outcome">Provider-neutral event outcome, such as success or failure.</param>
/// <param name="FailureReason">Provider-neutral failure reason safe for logs and administrator display.</param>
/// <param name="PropertiesJson">Serialized provider-neutral event properties. Values must not contain secrets, tokens, hashes, credentials, or protected payloads.</param>
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
        var provider = PersistedAuthenticationProviderKey.FromProvider(securityEvent.Provider);
        return new SecurityEventStorageRecord(
            securityEvent.Id,
            securityEvent.EventType,
            securityEvent.OccurredAt,
            securityEvent.UserId,
            securityEvent.TenantId,
            securityEvent.ActorUserId,
            securityEvent.SessionId,
            provider.ProviderTypeValue,
            provider.ProviderName,
            securityEvent.IpAddress,
            securityEvent.UserAgent,
            securityEvent.CorrelationId,
            securityEvent.Outcome,
            securityEvent.FailureReason,
            securityEvent.Properties != null ? JsonSerializer.Serialize(securityEvent.Properties) : null);
    }

    /// <summary>
    /// Creates a safe administrator summary from this storage record.
    /// </summary>
    /// <returns>The security event summary.</returns>
    public SecurityEventSummary ToSummary()
    {
        return new SecurityEventSummary(
            Id,
            EventType,
            OccurredAt,
            UserId,
            TenantId,
            ActorUserId,
            SessionId,
            ToProvider(ProviderType, ProviderName),
            IpAddress,
            UserAgent,
            CorrelationId,
            Outcome,
            FailureReason,
            ParseProperties(PropertiesJson));
    }

    private static AuthenticationProviderKey? ToProvider(string? providerType, string? providerName)
    {
        return new PersistedAuthenticationProviderKey(providerType, providerName).ToProviderKey();
    }

    private static Dictionary<string, string>? ParseProperties(string? propertiesJson)
    {
        if (string.IsNullOrWhiteSpace(propertiesJson))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(propertiesJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var properties = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String)
                {
                    properties[property.Name] = property.Value.ToString();
                }
            }

            return properties.Count == 0 ? null : properties;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
