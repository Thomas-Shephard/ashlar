namespace Ashlar.Auditing;

/// <summary>
/// Describes who or what caused a security-relevant operation.
/// </summary>
/// <param name="ActorUserId">The user that initiated the operation, when known.</param>
/// <param name="IpAddress">The source IP address, when safe to capture.</param>
/// <param name="UserAgent">The source user agent, when safe to capture.</param>
/// <param name="CorrelationId">The request or trace correlation id.</param>
/// <param name="Items">Additional non-secret audit metadata.</param>
public sealed record AuditContext(
    Guid? ActorUserId = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? CorrelationId = null,
    IReadOnlyDictionary<string, string>? Items = null);


