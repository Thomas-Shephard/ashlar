namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Request data used to create an authentication session.
/// </summary>
/// <param name="Lifetime">Requested session lifetime; <see langword="null" /> uses the service default.</param>
/// <param name="IpAddress">Client IP address captured by the host application. Treat as personal data.</param>
/// <param name="UserAgent">Client user-agent text captured by the host application. It may be user supplied.</param>
/// <param name="Metadata">Optional host-defined session metadata. Do not include secrets or bearer tokens.</param>
/// <param name="CorrelationId">Host-defined identifier for tracing the session issuance request.</param>
/// <param name="TenantId">Tenant scope for the issued session, or <see langword="null" /> for a global session.</param>
/// <param name="AuthenticatedAt">UTC time when primary authentication completed.</param>
/// <param name="PrimaryProvider">Provider that authenticated the primary credential.</param>
/// <param name="AdditionalVerificationAt">UTC time when additional verification completed, when available.</param>
/// <param name="AdditionalVerificationProvider">Provider that completed additional verification, when available.</param>
/// <param name="AdditionalVerificationFactor">Provider-neutral factor family that satisfied MFA or step-up verification, when available.</param>
public sealed record CreateAuthenticationSessionRequest(
    TimeSpan? Lifetime = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? Metadata = null,
    string? CorrelationId = null,
    Guid? TenantId = null,
    DateTimeOffset? AuthenticatedAt = null,
    AuthenticationProviderKey? PrimaryProvider = null,
    DateTimeOffset? AdditionalVerificationAt = null,
    AuthenticationProviderKey? AdditionalVerificationProvider = null,
    string? AdditionalVerificationFactor = null);
