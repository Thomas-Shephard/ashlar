using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Sessions;

/// <summary>Actor-bound request for revoking one session owned by the actor.</summary>
/// <param name="ActorUserId">The authenticated actor.</param><param name="ActorTenant">The actor scope.</param>
/// <param name="CurrentSessionId">The current session.</param><param name="FreshMfaProof">Actor-bound fresh proof.</param>
/// <param name="Audit">Required audit context.</param><param name="SessionId">The target session.</param><param name="Reason">Optional reason.</param>
public sealed record RevokeOwnAuthenticationSessionRequest(
    Guid ActorUserId,
    TenantContext ActorTenant,
    Guid CurrentSessionId,
    FreshMfaVerificationProof FreshMfaProof,
    AuditContext Audit,
    Guid SessionId,
    string? Reason = null);

/// <summary>Actor-bound request for revoking every other session owned by the actor.</summary>
/// <param name="ActorUserId">The authenticated actor.</param><param name="ActorTenant">The actor scope.</param>
/// <param name="CurrentSessionId">The current session.</param><param name="FreshMfaProof">Actor-bound fresh proof.</param>
/// <param name="Audit">Required audit context.</param><param name="Reason">Optional reason.</param>
public sealed record RevokeOwnOtherAuthenticationSessionsRequest(
    Guid ActorUserId,
    TenantContext ActorTenant,
    Guid CurrentSessionId,
    FreshMfaVerificationProof FreshMfaProof,
    AuditContext Audit,
    string? Reason = null);

/// <summary>Request bound to the currently presented session credential.</summary>
/// <param name="Token">The raw session token.</param><param name="Audit">Required audit context.</param><param name="Reason">Optional reason.</param>
public sealed record RevokeCurrentAuthenticationSessionRequest(
    string Token,
    AuditContext Audit,
    string? Reason = null);

/// <summary>Capability-bound request for revoking previously validated authentication state.</summary>
/// <param name="Session">The Ashlar-validated session capability.</param>
/// <param name="Audit">Required audit context.</param>
/// <param name="Reason">Optional reason.</param>
public sealed record RevokeValidatedAuthenticationSessionRequest(
    ValidatedAuthenticationSession Session,
    AuditContext Audit,
    string? Reason = null);

/// <summary>Capability-bound request for rolling back newly issued authentication state.</summary>
/// <param name="Session">The session returned by Ashlar session issuance.</param><param name="Audit">Required audit context.</param><param name="Reason">Optional reason.</param>
public sealed record RevokeIssuedAuthenticationSessionRequest(
    CreatedAuthenticationSession Session,
    AuditContext Audit,
    string? Reason = null);
