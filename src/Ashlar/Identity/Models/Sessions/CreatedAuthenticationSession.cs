namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Public details returned when an authentication session is created.
/// </summary>
/// <param name="Id">Unique identifier for this session.</param>
/// <param name="UserId">User that owns the session.</param>
/// <param name="TenantId">Tenant that bounds the session, or <see langword="null" /> for a global session.</param>
/// <param name="CreatedAt">UTC time when the session was issued.</param>
/// <param name="AuthenticatedAt">UTC time when primary authentication completed for this session.</param>
/// <param name="PrimaryProvider">Provider that verified the primary sign-in credential, when captured.</param>
/// <param name="ExpiresAt">UTC time after which the session is no longer valid.</param>
/// <param name="IpAddress">Client IP address captured for audit and session display, when stored.</param>
/// <param name="UserAgent">Client user-agent captured for audit and session display, when stored.</param>
/// <param name="Metadata">Provider-neutral session metadata safe for display.</param>
public sealed record CreatedAuthenticationSession(
    Guid Id,
    Guid UserId,
    Guid? TenantId,
    DateTimeOffset CreatedAt,
    DateTimeOffset? AuthenticatedAt,
    AuthenticationProviderKey? PrimaryProvider,
    DateTimeOffset ExpiresAt,
    string? IpAddress,
    string? UserAgent,
    string? Metadata);
