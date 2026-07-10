namespace Ashlar.Identity.Models.Sessions;

/// <summary>Immutable session snapshot produced by Ashlar's successful bearer-token validation path.</summary>
public sealed class ValidatedAuthenticationSession
{
    internal ValidatedAuthenticationSession(AuthenticationSession session)
    {
        Id = session.Id;
        UserId = session.UserId;
        TenantId = session.TenantId;
        AuthenticatedAt = session.AuthenticatedAt?.ToUniversalTime();
        AdditionalVerificationAt = session.AdditionalVerificationAt?.ToUniversalTime();
        AdditionalVerificationProvider = session.AdditionalVerificationProvider;
        AdditionalVerificationFactor = session.AdditionalVerificationFactor;
        ExpiresAt = session.ExpiresAt.ToUniversalTime();
    }

    /// <summary>Validated session identifier.</summary>
    public Guid Id { get; }
    /// <summary>User that owns the validated session.</summary>
    public Guid UserId { get; }
    /// <summary>Tenant that bounds the validated session.</summary>
    public Guid? TenantId { get; }
    /// <summary>UTC primary-authentication time captured during validation.</summary>
    public DateTimeOffset? AuthenticatedAt { get; }
    /// <summary>UTC additional-verification time captured during validation.</summary>
    public DateTimeOffset? AdditionalVerificationAt { get; }
    /// <summary>Additional-verification provider captured during validation.</summary>
    public AuthenticationProviderKey? AdditionalVerificationProvider { get; }
    /// <summary>Additional-verification factor captured during validation.</summary>
    public string? AdditionalVerificationFactor { get; }
    /// <summary>UTC expiry of the validated session.</summary>
    public DateTimeOffset ExpiresAt { get; }
}

/// <summary>
/// Result returned after validating a presented bearer token.
/// </summary>
/// <param name="Succeeded">Whether validation produced an active <paramref name="Session" />.</param>
/// <param name="Session">The matching <paramref name="Session" /> when validation succeeds.</param>
/// <param name="UserId">The owner of the matching record, when known.</param>
/// <param name="Status">Validation outcome. Avoid exposing precise failure status to untrusted clients.</param>
public sealed record ValidateAuthenticationSessionResult(
    bool Succeeded,
    AuthenticationSession? Session,
    Guid? UserId,
    AuthenticationSessionValidationStatus Status)
{
    /// <summary>
    /// Capability available only from Ashlar's built-in successful token-validation path. Custom session validators may
    /// authenticate callers but do not enable fresh-verification proof issuance.
    /// </summary>
    public ValidatedAuthenticationSession? ValidatedSession { get; internal init; }

    /// <summary>
    /// A generic failed validation result with no matching session.
    /// </summary>
    public static ValidateAuthenticationSessionResult Failed { get; } =
        new(false, null, null, AuthenticationSessionValidationStatus.Failed);
}
