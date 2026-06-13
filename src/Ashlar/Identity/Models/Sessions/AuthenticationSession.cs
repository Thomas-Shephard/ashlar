namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Persisted bearer session issued after primary authentication and optional additional verification.
/// </summary>
public sealed class AuthenticationSession
{
    /// <summary>
    /// Unique identifier for this session.
    /// </summary>
    public required Guid Id { get; init; }
    /// <summary>
    /// User that owns the session.
    /// </summary>
    public required Guid UserId { get; init; }
    /// <summary>
    /// Tenant that bounds the session, or <see langword="null" /> for a global session.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Hash of the raw bearer session token. The raw token is not stored on the session.
    /// </summary>
    public required string TokenHash { get; init; }
    /// <summary>
    /// UTC time when the session was issued.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }
    /// <summary>
    /// UTC time when primary authentication completed for this session.
    /// </summary>
    public DateTimeOffset? AuthenticatedAt { get; set; }
    /// <summary>
    /// Provider that verified the primary sign-in credential, when captured.
    /// </summary>
    public AuthenticationProviderKey? PrimaryProvider { get; set; }
    /// <summary>
    /// UTC time when MFA or step-up verification was satisfied, when captured.
    /// </summary>
    public DateTimeOffset? AdditionalVerificationAt { get; set; }
    /// <summary>
    /// Provider that satisfied the additional verification challenge, when captured.
    /// </summary>
    public AuthenticationProviderKey? AdditionalVerificationProvider { get; set; }
    /// <summary>
    /// Provider-neutral factor family that satisfied MFA or step-up verification.
    /// </summary>
    public string? AdditionalVerificationFactor { get; set; }
    /// <summary>
    /// UTC time after which the session is no longer valid.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
    /// <summary>
    /// UTC time when validation last observed this session.
    /// </summary>
    public DateTimeOffset? LastSeenAt { get; set; }
    /// <summary>
    /// UTC time when the session was revoked, or <see langword="null" /> while it remains usable.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }
    /// <summary>
    /// Provider-neutral, display-safe reason recorded when the session is revoked. Do not include secrets, tokens, or credentials.
    /// </summary>
    public string? RevocationReason { get; set; }
    /// <summary>
    /// Client IP address captured for audit and session display. Treat as personal data.
    /// </summary>
    public string? IpAddress { get; set; }
    /// <summary>
    /// Client user-agent captured for audit and session display. Treat as user-supplied data.
    /// </summary>
    public string? UserAgent { get; set; }
    /// <summary>
    /// Provider-neutral session metadata. Do not store secrets or raw tokens in this value.
    /// </summary>
    public string? Metadata { get; set; }

    /// <summary>
    /// Determines whether the session can currently be used.
    /// </summary>
    /// <param name="now">UTC time used for expiry evaluation.</param>
    /// <returns><see langword="true" /> when the session is not revoked and has not expired.</returns>
    public bool IsActive(DateTimeOffset now)
    {
        return RevokedAt == null && ExpiresAt > now;
    }
}
