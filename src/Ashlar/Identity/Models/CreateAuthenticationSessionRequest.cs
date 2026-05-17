namespace Ashlar.Identity.Models;

/// <summary>
/// Request data used to create an authentication session.
/// </summary>
/// <param name="Lifetime">The lifetime value.</param>
/// <param name="IpAddress">The ip address value.</param>
/// <param name="UserAgent">The user agent value.</param>
/// <param name="Metadata">The metadata value.</param>
/// <param name="CorrelationId">The correlation id value.</param>
/// <param name="TenantId">The tenant id value.</param>
public sealed record CreateAuthenticationSessionRequest(
    TimeSpan? Lifetime = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? Metadata = null,
    string? CorrelationId = null,
    Guid? TenantId = null);
