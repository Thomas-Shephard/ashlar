namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Carries request metadata supplied by the host application during authentication.
/// </summary>
/// <param name="Email">Email address involved in the request, when available.</param>
/// <param name="TenantId">Tenant scope supplied by the host application.</param>
/// <param name="IpAddress">Client IP address captured by the host application; treat it as personal data.</param>
/// <param name="UserAgent">Client user-agent text captured by the host application; it may be user supplied.</param>
/// <param name="CorrelationId">Host-defined identifier for tracing the request across systems.</param>
/// <param name="ReturnUrl">Post-authentication return URL validated by the host application.</param>
/// <param name="Items">Additional host-defined context. Do not include secrets, credentials, or bearer tokens.</param>
/// <param name="UserId">Known user identifier when the request has already resolved an account.</param>
/// <param name="CurrentSessionId">Existing session targeted by a step-up authentication ceremony.</param>
public sealed record AuthenticationContext(
    string? Email = null,
    Guid? TenantId = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? CorrelationId = null,
    string? ReturnUrl = null,
    IReadOnlyDictionary<string, string>? Items = null,
    Guid? UserId = null,
    Guid? CurrentSessionId = null);
