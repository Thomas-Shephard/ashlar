namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Manages provider-neutral authentication session lifecycle operations.
/// </summary>
public interface IAuthenticationSessionService
{
    /// <summary>Purpose required for fresh proofs authorizing self-service session management.</summary>
    public const string SelfServiceProofPurpose = "session-management";

    /// <summary>
    /// Creates and persists a new authentication session after Ashlar has completed authentication.
    /// </summary>
    /// <param name="authenticationResult">Successful Ashlar authentication result carrying the internal session-issuance proof.</param>
    /// <param name="request">Session lifetime, tenant, audit, and client metadata supplied by the host application.</param>
    /// <param name="cancellationToken">A token that can cancel session creation.</param>
    /// <returns>Public session details and the raw bearer token that must be returned to the client once. Token hashes are not returned.</returns>
    /// <remarks>Host applications cannot mint sessions from caller-supplied user identifiers; session issuance requires an Ashlar-verified authentication completion result.</remarks>
    Task<CreateAuthenticationSessionResult> CreateSessionAsync(
        MfaAuthenticationResult authenticationResult,
        CreateAuthenticationSessionRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a presented raw session token.
    /// </summary>
    /// <param name="token">The raw bearer token presented by a client. Do not log or persist this value.</param>
    /// <param name="cancellationToken">A token that can cancel validation.</param>
    /// <returns>Validation outcome and matching session when the token is active.</returns>
    Task<ValidateAuthenticationSessionResult> ValidateSessionAsync(
        string? token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks an existing active session as recently verified after Ashlar has completed step-up MFA.
    /// </summary>
    /// <param name="authenticationResult">Successful Ashlar MFA result carrying the internal step-up marking proof.</param>
    /// <param name="request">Active session and factor metadata to mark as freshly verified.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns>Updated active session with step-up verification metadata, or a failure status.</returns>
    /// <remarks>Host applications cannot mark step-up with caller-controlled user, session, provider, and factor data alone.</remarks>
    Task<Result<AuthenticationSession>> MarkStepUpVerifiedAsync(
        MfaAuthenticationResult authenticationResult,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes one authentication session owned by the authenticated actor.
    /// </summary>
    /// <param name="request">Actor, current session, fresh proof, target session, tenant scope, and audit context.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns><see langword="true" /> when the target session was revoked.</returns>
    /// <remarks>Revoking or expiring the fresh proof's source session immediately invalidates the proof.</remarks>
    Task<bool> RevokeSessionForCurrentUserAsync(RevokeOwnAuthenticationSessionRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all other authentication sessions owned by the authenticated actor.
    /// </summary>
    /// <param name="request">Actor, current session, fresh proof, tenant scope, and audit context.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of other sessions revoked.</returns>
    /// <remarks>Revoking or expiring the fresh proof's source session immediately invalidates the proof.</remarks>
    Task<int> RevokeOtherSessionsForCurrentUserAsync(RevokeOwnOtherAuthenticationSessionsRequest request, CancellationToken cancellationToken = default);

    /// <summary>Revokes the session identified by a currently presented raw session token.</summary>
    /// <param name="request">The raw token, audit context, and optional reason.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns><see langword="true" /> when the presented active session was revoked.</returns>
    Task<bool> RevokeCurrentSessionAsync(RevokeCurrentAuthenticationSessionRequest request, CancellationToken cancellationToken = default);

    /// <summary>Revokes a session using the capability returned by successful validation.</summary>
    /// <param name="request">The validated session capability, audit context, and optional reason.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns><see langword="true" /> when the validated session was revoked.</returns>
    Task<bool> RevokeValidatedSessionAsync(RevokeValidatedAuthenticationSessionRequest request, CancellationToken cancellationToken = default);

    /// <summary>Rolls back a newly issued session using its Ashlar-issued authentication capability.</summary>
    /// <param name="request">The issued session, audit context, and optional reason.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns><see langword="true" /> when the matching issued session was revoked.</returns>
    Task<bool> RevokeIssuedSessionAsync(RevokeIssuedAuthenticationSessionRequest request, CancellationToken cancellationToken = default);
}
