namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Coordinates primary authentication, MFA requirements, and step-up factor verification.
/// </summary>
public interface IAuthenticationOrchestrator
{
    /// <summary>
    /// Authenticates a primary credential and determines whether MFA is required before a session is issued.
    /// </summary>
    /// <param name="context">Request, tenant, client, and audit context supplied by the host application.</param>
    /// <param name="primaryAssertion">Primary credential assertion to verify. Treat as sensitive unless the provider documents otherwise.</param>
    /// <param name="options">Optional MFA orchestration settings for this authentication attempt.</param>
    /// <param name="cancellationToken">A token that can cancel the authentication attempt.</param>
    /// <returns>An MFA-aware result. The host should issue an application session only when the result succeeds.</returns>
    Task<MfaAuthenticationResult> AuthenticateAsync(
        AuthenticationContext context,
        IAuthenticationAssertion primaryAssertion,
        MfaOrchestrationOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a secondary factor for an existing MFA or step-up handshake.
    /// </summary>
    /// <param name="handshakeToken">The raw handshake token presented by the client. Do not log or persist this value.</param>
    /// <param name="factorType">The required factor family to satisfy.</param>
    /// <param name="context">Request, tenant, client, and audit context supplied by the host application.</param>
    /// <param name="assertion">Secondary factor assertion to verify. Treat as sensitive unless the provider documents otherwise.</param>
    /// <param name="cancellationToken">A token that can cancel factor verification.</param>
    /// <returns>An MFA-aware result describing whether the handshake is complete, incomplete, failed, or rate limited.</returns>
    Task<MfaAuthenticationResult> VerifyFactorAsync(
        string? handshakeToken,
        string factorType,
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        CancellationToken cancellationToken = default);
}
