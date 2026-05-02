using Ashlar.Identity.Models;

namespace Ashlar.Auditing;

/// <summary>
/// Structured provider-neutral event for security-sensitive Ashlar operations.
/// </summary>
public sealed record AshlarSecurityEvent
{
    public required Guid Id { get; init; }

    public required string EventType { get; init; }

    public required DateTimeOffset OccurredAt { get; init; }

    public Guid? UserId { get; init; }

    public Guid? SessionId { get; init; }

    public AuthenticationProviderKey? Provider { get; init; }

    public string? IpAddress { get; init; }

    public string? UserAgent { get; init; }

    public string? CorrelationId { get; init; }

    public string? Outcome { get; init; }

    public string? FailureReason { get; init; }

    public IReadOnlyDictionary<string, string>? Properties { get; init; }
}
