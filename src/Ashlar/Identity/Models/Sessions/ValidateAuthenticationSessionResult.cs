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
        PrimaryProvider = session.PrimaryProvider;
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
    /// <summary>Primary-authentication provider captured during validation.</summary>
    public AuthenticationProviderKey? PrimaryProvider { get; }
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
public sealed class ValidateAuthenticationSessionResult
{
    private ValidateAuthenticationSessionResult(
        AuthenticationSessionValidationStatus status,
        ValidatedAuthenticationSession? validatedSession = null)
    {
        Status = status;
        ValidatedSession = validatedSession;
    }

    /// <summary>Validation outcome. Avoid exposing precise failure status to untrusted clients.</summary>
    public AuthenticationSessionValidationStatus Status { get; }

    /// <summary>
    /// Capability available only from Ashlar's built-in successful token-validation path. Security-sensitive consumers
    /// must require this capability rather than trusting mutable session result fields.
    /// </summary>
    public ValidatedAuthenticationSession? ValidatedSession { get; }

    internal static ValidateAuthenticationSessionResult Success(AuthenticationSession session) =>
        new(AuthenticationSessionValidationStatus.Succeeded, new ValidatedAuthenticationSession(session));

    /// <summary>
    /// A generic failed validation result with no matching session.
    /// </summary>
    public static ValidateAuthenticationSessionResult Failed { get; } =
        new(AuthenticationSessionValidationStatus.Failed);

    /// <summary>An expired-session validation result.</summary>
    public static ValidateAuthenticationSessionResult Expired { get; } =
        new(AuthenticationSessionValidationStatus.Expired);

    /// <summary>A revoked-session validation result.</summary>
    public static ValidateAuthenticationSessionResult Revoked { get; } =
        new(AuthenticationSessionValidationStatus.Revoked);
}
