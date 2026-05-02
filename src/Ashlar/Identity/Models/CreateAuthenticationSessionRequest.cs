namespace Ashlar.Identity.Models;

/// <summary>
/// Request data used to create an authentication session.
/// </summary>
public sealed record CreateAuthenticationSessionRequest(
    TimeSpan? Lifetime = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? Metadata = null,
    string? CorrelationId = null);
