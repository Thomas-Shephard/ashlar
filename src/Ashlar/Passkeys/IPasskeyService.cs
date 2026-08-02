namespace Ashlar.Passkeys;

/// <summary>
/// Coordinates passkey registration, authentication, and credential management flows.
/// </summary>
/// <remarks>
/// Factor flows use Ashlar MFA handshakes. Configure identity, credential, passkey challenge, and authentication handshake
/// repositories when resolving this service.
/// </remarks>
public interface IPasskeyService
{
    /// <summary>Purpose required when minting proofs for passkey registration.</summary>
    public const string RegistrationProofPurpose = "passkey-registration";

    /// <summary>Purpose required when minting proofs for passkey management.</summary>
    public const string ManagementProofPurpose = "passkey-management";

    /// <summary>
    /// Starts a passkey registration ceremony.
    /// </summary>
    /// <param name="verification">The authenticated registration capability.</param>
    /// <param name="request">The registration request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The browser ceremony options.</returns>
    /// <remarks>
    /// This is the self-service registration path for the authenticated account owner. The verification context must include an
    /// Ashlar-issued fresh-verification proof minted for <c>passkey-registration</c>. Accounts with an existing usable
    /// additional-verification factor require fresh MFA proof; first-passkey setup may use fresh primary-authentication
    /// proof from the current authenticated session. The target user must exist, be in the verification tenant scope,
    /// and have an account state that can sign in.
    /// </remarks>
    Task<PasskeyCeremonyOptions> StartRegistrationAsync(PasskeyRegistrationVerificationContext verification, StartPasskeyRegistrationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Completes a passkey registration ceremony.
    /// </summary>
    /// <param name="verification">The authenticated registration capability.</param>
    /// <param name="request">The completion request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// The same proof purpose, session, tenant, and user binding is checked again before credential persistence. The
    /// challenge user is reloaded before credential persistence. The actor user, verification tenant, challenge tenant,
    /// proof tenant, and stored user tenant must all match, and the account must still be able to sign in.
    /// </remarks>
    Task<Result> CompleteRegistrationAsync(PasskeyRegistrationVerificationContext verification, CompletePasskeyRegistrationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Starts a passkey authentication ceremony.
    /// </summary>
    /// <param name="request">The authentication request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The browser ceremony options when challenge creation is allowed.</returns>
    Task<Result<PasskeyCeremonyOptions>> StartAuthenticationAsync(StartPasskeyAuthenticationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Completes a passkey authentication ceremony.
    /// </summary>
    /// <param name="request">The completion request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The authentication result.</returns>
    Task<PasskeyAuthenticationResult> CompleteAuthenticationAsync(CompletePasskeyAuthenticationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Starts a passkey MFA factor ceremony for an existing handshake.
    /// </summary>
    /// <param name="request">The factor request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The browser ceremony options when the handshake can use passkeys.</returns>
    Task<Result<PasskeyCeremonyOptions>> StartFactorAsync(StartPasskeyFactorRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Completes a passkey MFA factor ceremony for an existing handshake.
    /// </summary>
    /// <param name="request">The completion request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The authentication result.</returns>
    Task<PasskeyAuthenticationResult> CompleteFactorAsync(CompletePasskeyFactorRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Lists passkeys registered for the current authenticated account owner.
    /// </summary>
    /// <param name="actor">The validated self-service actor capability.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The operation result containing the registered passkeys when the management boundary succeeds.</returns>
    Task<Result<IReadOnlyList<PasskeyCredentialSummary>>> ListAsync(AccountSecurityActorContext actor, CancellationToken cancellationToken = default);
    /// <summary>
    /// Renames a passkey display name for the current authenticated account owner.
    /// </summary>
    /// <param name="actor">The validated self-service actor capability.</param>
    /// <param name="request">The passkey rename operation data.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The operation result. Successful mutations and audit records commit atomically.</returns>
    Task<Result> RenameAsync(AccountSecurityActorContext actor, RenamePasskeyRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Revokes a passkey credential for the current authenticated account owner.
    /// </summary>
    /// <param name="actor">The validated self-service actor capability.</param>
    /// <param name="request">The passkey revocation operation data.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The operation result. Successful mutations and audit records commit atomically.</returns>
    Task<Result> RevokeAsync(AccountSecurityActorContext actor, RevokePasskeyRequest request, CancellationToken cancellationToken = default);
}
