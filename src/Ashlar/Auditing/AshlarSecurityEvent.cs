using Ashlar.Identity.Models;

namespace Ashlar.Auditing;

/// <summary>
/// Structured provider-neutral event for security-sensitive Ashlar operations.
/// </summary>
public sealed record AshlarSecurityEvent
{
    /// <summary>
    /// Unique identifier for this specific audit event instance.
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// Gets or sets the event type value.
    /// </summary>
    public required string EventType { get; init; }

    /// <summary>
    /// Gets or sets the occurred at value.
    /// </summary>
    public required DateTimeOffset OccurredAt { get; init; }

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
    /// Gets or sets the outcome value.
    /// </summary>
    public string? Outcome { get; init; }

    /// <summary>
    /// Gets or sets the failure reason value.
    /// </summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// Gets or sets the properties value.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Properties { get; init; }
}
