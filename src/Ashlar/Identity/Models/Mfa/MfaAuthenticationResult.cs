namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Lists the outcomes of an MFA-aware authentication flow.
/// </summary>
public enum MfaAuthenticationStatus
{
    /// <summary>
    /// Authentication failed.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Authentication completed successfully and the host may issue or continue an application session.
    /// </summary>
    Succeeded = 1,
    /// <summary>
    /// Primary authentication succeeded, but the host must complete MFA before issuing a full session.
    /// </summary>
    MfaRequired = 2,
    /// <summary>
    /// The MFA handshake exists, but not all required factors have been verified.
    /// </summary>
    HandshakeIncomplete = 3,
    /// <summary>
    /// Authentication was blocked by a rate limiter. Treat the result as a failed authentication attempt.
    /// </summary>
    RateLimited = 4
}

/// <summary>
/// Result returned by MFA-aware authentication flows.
/// </summary>
/// <param name="Status">Outcome of the MFA-aware authentication flow.</param>
/// <param name="User">The authenticated user when authentication succeeds.</param>
/// <param name="HandshakeToken">The raw handshake token when more MFA factors are required. Do not log or persist this value.</param>
/// <param name="RequiredFactors">The MFA factors still required for the handshake.</param>
/// <param name="Claims">Additional claims produced by the authentication provider.</param>
/// <param name="ErrorMessage">A generic, display-safe error message when authentication fails.</param>
/// <param name="FreshMfaSatisfied">Whether this result came from a fresh MFA ceremony suitable for step-up decisions.</param>
/// <remarks>
/// Creates an MFA authentication result.
/// </remarks>
public sealed class MfaAuthenticationResult(
    MfaAuthenticationStatus Status,
    IUser? User = null,
    string? HandshakeToken = null,
    IEnumerable<string>? RequiredFactors = null,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? Claims = null,
    string? ErrorMessage = null,
    bool FreshMfaSatisfied = false)
{

    /// <summary>Gets the outcome of the MFA-aware authentication flow.</summary>
    public MfaAuthenticationStatus Status { get; } = Status;
    /// <summary>Gets the authenticated user when authentication succeeds.</summary>
    public IUser? User { get; } = User;
    /// <summary>Gets the raw handshake token when more MFA factors are required.</summary>
    public string? HandshakeToken { get; } = HandshakeToken;
    /// <summary>Gets the MFA factors still required for the handshake.</summary>
    public IEnumerable<string>? RequiredFactors { get; } = RequiredFactors;
    /// <summary>Gets additional claims produced by the authentication provider.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? Claims { get; } = Claims;
    /// <summary>Gets a display-safe error message when authentication fails.</summary>
    public string? ErrorMessage { get; } = ErrorMessage;
    /// <summary>Gets whether this result came from a fresh MFA ceremony.</summary>
    public bool FreshMfaSatisfied { get; } = FreshMfaSatisfied;
    /// <summary>Gets whether provider-requested credential changes were persisted.</summary>
    public bool CredentialUpdatePersisted { get; init; }

    internal RememberedMfaDeviceCreationProof? RememberedDeviceCreationProof { get; init; }

    internal AuthenticationSessionIssuanceProof? SessionIssuanceProof { get; init; }

    internal StepUpSessionMarkingProof? StepUpSessionMarkingProof { get; init; }
}

internal sealed class RememberedMfaDeviceCreationProof(
    Guid userId,
    Guid? tenantId,
    Guid sourceHandshakeId,
    DateTimeOffset issuedAt,
    DateTimeOffset expiresAt)
{
    private int _consumed;

    internal Guid UserId { get; } = userId;
    internal Guid? TenantId { get; } = tenantId;
    internal Guid SourceHandshakeId { get; } = sourceHandshakeId;

    internal bool TryConsume(DateTimeOffset now) =>
        now >= issuedAt && now < expiresAt && Interlocked.Exchange(ref _consumed, 1) == 0;

    internal static RememberedMfaDeviceCreationProof Create(
        Guid userId,
        Guid? tenantId,
        Guid sourceHandshakeId,
        DateTimeOffset now) => new(userId, tenantId, sourceHandshakeId, now, AuthenticationProofExpiry.From(now));
}

internal enum AuthenticationSessionIssuanceAudience
{
    PrimaryAuthentication,
    LoginTimeMfa
}

internal sealed class AuthenticationSessionIssuanceProof(
    Guid userId,
    AuthenticationSessionIssuanceAudience audience,
    AuthenticationProviderKey? primaryProvider,
    AuthenticationProviderKey? additionalVerificationProvider,
    string? additionalVerificationFactor,
    DateTimeOffset issuedAt,
    DateTimeOffset expiresAt)
{
    private int _consumed;

    internal Guid UserId { get; } = userId;
    internal AuthenticationSessionIssuanceAudience Audience { get; } = audience;
    internal AuthenticationProviderKey? PrimaryProvider { get; } = primaryProvider;
    internal AuthenticationProviderKey? AdditionalVerificationProvider { get; } = additionalVerificationProvider;
    internal string? AdditionalVerificationFactor { get; } = additionalVerificationFactor;
    internal DateTimeOffset IssuedAt { get; } = issuedAt;

    internal bool TryConsume(DateTimeOffset now) =>
        now >= IssuedAt && now < expiresAt && Interlocked.Exchange(ref _consumed, 1) == 0;

    internal static AuthenticationSessionIssuanceProof CreatePrimary(
        Guid userId,
        AuthenticationProviderKey? primaryProvider,
        DateTimeOffset now) =>
        new(userId, AuthenticationSessionIssuanceAudience.PrimaryAuthentication, primaryProvider, null, null, now, AuthenticationProofExpiry.From(now));

    internal static AuthenticationSessionIssuanceProof CreateLoginMfa(
        Guid userId,
        AuthenticationProviderKey? primaryProvider,
        AuthenticationProviderKey provider,
        string factor,
        DateTimeOffset now) =>
        new(userId, AuthenticationSessionIssuanceAudience.LoginTimeMfa, primaryProvider, provider, factor, now, AuthenticationProofExpiry.From(now));
}

internal sealed class StepUpSessionMarkingProof(
    Guid userId,
    Guid targetSessionId,
    AuthenticationProviderKey provider,
    string factor,
    DateTimeOffset issuedAt,
    DateTimeOffset expiresAt)
{
    private int _consumed;

    internal Guid UserId { get; } = userId;
    internal AuthenticationProviderKey Provider { get; } = provider;
    internal string Factor { get; } = factor;
    internal DateTimeOffset IssuedAt { get; } = issuedAt;

    internal bool TryConsume(Guid sessionId, DateTimeOffset now)
    {
        if (sessionId != targetSessionId || now < IssuedAt || now >= expiresAt)
        {
            return false;
        }

        return Interlocked.Exchange(ref _consumed, 1) == 0;
    }

    internal static StepUpSessionMarkingProof Create(
        Guid userId,
        Guid targetSessionId,
        AuthenticationProviderKey provider,
        string factor,
        DateTimeOffset now) =>
        new(userId, targetSessionId, provider, factor, now, AuthenticationProofExpiry.From(now));
}

file static class AuthenticationProofExpiry
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    internal static DateTimeOffset From(DateTimeOffset issuedAt) =>
        DateTimeOffset.MaxValue - issuedAt < Lifetime ? DateTimeOffset.MaxValue : issuedAt.Add(Lifetime);
}
