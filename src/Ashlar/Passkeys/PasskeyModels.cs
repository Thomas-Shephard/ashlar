using System.Text.Json;
using Ashlar.Auditing;

namespace Ashlar.Passkeys;

/// <summary>
/// Request to start self-service passkey registration for the authenticated account owner.
/// </summary>
/// <param name="ActorUserId">Authenticated user performing the self-service operation. This user owns the pending passkey registration.</param>
/// <param name="DisplayName">The passkey display name.</param>
/// <param name="Audit">Required audit metadata whose actor must match <paramref name="ActorUserId" />. Do not include proof material or browser ceremony payloads.</param>
public sealed record StartPasskeyRegistrationRequest(Guid ActorUserId, string DisplayName, AuditContext Audit)
{
    /// <summary>Fresh MFA proof for the current authenticated session. Obtain it from <c>StepUpAuthenticationService.CreateFreshMfaProof</c>; do not bind it from request JSON.</summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; init; }
    /// <summary>Fresh primary-authentication proof for passkey registration only when the account has no usable MFA factor. Obtain it from <c>StepUpAuthenticationService.CreateFreshPrimaryAuthenticationProof</c>; do not bind it from request JSON.</summary>
    public FreshPrimaryAuthenticationProof? FreshPrimaryAuthenticationProof { get; init; }
    /// <summary>Current Ashlar session ID from the authenticated request. It must match the supplied fresh-verification proof.</summary>
    public Guid? CurrentSessionId { get; init; }
    /// <summary>Tenant scope for the registration. Omit or use <see cref="TenantContext.Global" /> for global users; this is not an all-tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
}

/// <summary>
/// Request to complete self-service passkey registration for the authenticated account owner.
/// </summary>
/// <param name="ChallengeId">The challenge id.</param>
/// <param name="CredentialResponse">The browser credential response.</param>
/// <param name="DisplayName">The optional passkey display name.</param>
/// <param name="ActorUserId">Authenticated user completing the self-service operation. This user must match the challenge and proof.</param>
/// <param name="Audit">Required audit metadata whose actor must match <paramref name="ActorUserId" />. Do not include proof material or browser ceremony payloads.</param>
public sealed record CompletePasskeyRegistrationRequest(Guid ChallengeId, JsonElement CredentialResponse, string? DisplayName, Guid ActorUserId, AuditContext Audit)
{
    /// <summary>Fresh MFA proof for the current authenticated session. Obtain it from <c>StepUpAuthenticationService.CreateFreshMfaProof</c>; do not bind it from request JSON.</summary>
    public FreshMfaVerificationProof? FreshMfaProof { get; init; }
    /// <summary>Fresh primary-authentication proof for passkey registration only when the account has no usable MFA factor. Obtain it from <c>StepUpAuthenticationService.CreateFreshPrimaryAuthenticationProof</c>; do not bind it from request JSON.</summary>
    public FreshPrimaryAuthenticationProof? FreshPrimaryAuthenticationProof { get; init; }
    /// <summary>Current Ashlar session ID from the authenticated request. It must match the supplied fresh-verification proof and stored challenge binding.</summary>
    public Guid? CurrentSessionId { get; init; }
    /// <summary>Tenant scope that must match the challenge, proof, and user. Omit or use <see cref="TenantContext.Global" /> for global users only.</summary>
    public TenantContext? Tenant { get; init; }
}
/// <summary>
/// Represents a request to start passkey authentication.
/// </summary>
/// <param name="UserId">The optional user id for user-scoped ceremonies.</param>
/// <param name="Audit">The optional audit context.</param>
public sealed record StartPasskeyAuthenticationRequest(Guid? UserId = null, AuditContext? Audit = null)
{
    /// <summary>Tenant scope. Omit or use <see cref="TenantContext.Global" /> for global users; this is not an all-tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
}
/// <summary>
/// Represents a request to complete passkey authentication.
/// </summary>
/// <param name="ChallengeId">The challenge id.</param>
/// <param name="AssertionResponse">The browser assertion response.</param>
/// <param name="TenantId">The optional tenant constraint for authentication.</param>
/// <param name="Audit">The optional audit context.</param>
public sealed record CompletePasskeyAuthenticationRequest(Guid ChallengeId, JsonElement AssertionResponse, Guid? TenantId = null, AuditContext? Audit = null);
/// <summary>
/// Represents a request to start passkey MFA factor verification.
/// </summary>
/// <param name="HandshakeToken">The MFA handshake token.</param>
/// <param name="FactorType">The requested factor type.</param>
/// <param name="Audit">The optional audit context.</param>
public sealed record StartPasskeyFactorRequest(string? HandshakeToken, string FactorType = "passkey", AuditContext? Audit = null)
{
    /// <summary>Tenant scope for the pending authentication handshake. Omit or use <see cref="TenantContext.Global" /> for global users; this is not an all-tenant scope.</summary>
    public TenantContext? Tenant { get; init; }
}
/// <summary>
/// Represents a request to complete passkey MFA factor verification.
/// </summary>
/// <param name="ChallengeId">The challenge id.</param>
/// <param name="AssertionResponse">The browser assertion response.</param>
/// <param name="HandshakeToken">The MFA handshake token.</param>
/// <param name="FactorType">The requested factor type.</param>
/// <param name="TenantId">The optional tenant constraint for factor authentication.</param>
/// <param name="Audit">The optional audit context.</param>
public sealed record CompletePasskeyFactorRequest(Guid ChallengeId, JsonElement AssertionResponse, string? HandshakeToken, string FactorType = "passkey", Guid? TenantId = null, AuditContext? Audit = null);
/// <summary>
/// Self-service request to list passkeys for the current authenticated account owner.
/// </summary>
/// <param name="ActorUserId">Current authenticated user. Only this user's passkeys are returned.</param>
/// <param name="Tenant">Explicit tenant scope for the current user; use <see cref="TenantContext.Global" /> for global users.</param>
/// <param name="CurrentSessionId">Non-empty current Ashlar session id from the authenticated request; it must match <paramref name="FreshMfaProof" />.</param>
/// <param name="FreshMfaProof">Ashlar-issued fresh MFA proof minted for <c>passkey-management</c>; rejected when its source session is missing, expired, or revoked.</param>
/// <param name="Audit">Required audit metadata recorded with the inventory read.</param>
public sealed record ListPasskeysRequest(Guid ActorUserId, TenantContext Tenant, Guid CurrentSessionId, FreshMfaVerificationProof FreshMfaProof, AuditContext Audit);
/// <summary>
/// Self-service request to rename one of the current authenticated account owner's passkeys.
/// </summary>
/// <param name="ActorUserId">Current authenticated user. This user must own the credential.</param>
/// <param name="Tenant">Explicit tenant scope that must match the actor and fresh proof.</param>
/// <param name="CurrentSessionId">Non-empty current Ashlar session id from the authenticated request; it must match <paramref name="FreshMfaProof" />.</param>
/// <param name="FreshMfaProof">Ashlar-issued fresh MFA proof minted for <c>passkey-management</c>; rejected when its source session is missing, expired, or revoked.</param>
/// <param name="CredentialId">The passkey credential id.</param>
/// <param name="DisplayName">The new display name.</param>
/// <param name="Audit">Required audit metadata recorded atomically with the mutation.</param>
public sealed record RenamePasskeyRequest(Guid ActorUserId, TenantContext Tenant, Guid CurrentSessionId, FreshMfaVerificationProof FreshMfaProof, Guid CredentialId, string DisplayName, AuditContext Audit);
/// <summary>
/// Self-service request to revoke one of the current authenticated account owner's passkeys.
/// </summary>
/// <param name="ActorUserId">Current authenticated user. This user must own the credential.</param>
/// <param name="Tenant">Explicit tenant scope that must match the actor and fresh proof.</param>
/// <param name="CurrentSessionId">Non-empty current Ashlar session id from the authenticated request; it must match <paramref name="FreshMfaProof" />.</param>
/// <param name="FreshMfaProof">Ashlar-issued fresh MFA proof minted for <c>passkey-management</c>; rejected when its source session is missing, expired, or revoked.</param>
/// <param name="CredentialId">The passkey credential id.</param>
/// <param name="Audit">Required audit metadata recorded atomically with the mutation.</param>
public sealed record RevokePasskeyRequest(Guid ActorUserId, TenantContext Tenant, Guid CurrentSessionId, FreshMfaVerificationProof FreshMfaProof, Guid CredentialId, AuditContext Audit);

/// <summary>
/// Represents browser options for a passkey ceremony.
/// </summary>
/// <param name="ChallengeId">The challenge id.</param>
/// <param name="OptionsJson">The serialized WebAuthn options.</param>
/// <param name="ExpiresAt">The challenge expiry timestamp.</param>
public sealed record PasskeyCeremonyOptions(Guid ChallengeId, string OptionsJson, DateTimeOffset ExpiresAt);
/// <summary>
/// Represents the result of a passkey authentication flow.
/// </summary>
/// <param name="Succeeded">Whether authentication fully succeeded.</param>
/// <param name="User">The authenticated user, when available.</param>
/// <param name="Credential">The passkey credential summary, when available.</param>
/// <param name="FailureCode">The failure code, when authentication failed.</param>
/// <param name="AuthenticationStatus">The MFA-aware authentication status.</param>
/// <param name="HandshakeToken">The MFA handshake token, when additional factors are required.</param>
/// <param name="RequiredFactors">The remaining required factors.</param>
/// <param name="ErrorMessage">The display-safe error message.</param>
/// <param name="AuthenticationResult">The Ashlar authentication result required for session issuance or step-up marking when authentication succeeds.</param>
public sealed record PasskeyAuthenticationResult(
    bool Succeeded,
    IUser? User,
    PasskeyCredentialSummary? Credential,
    AshlarFailureCode? FailureCode = null,
    MfaAuthenticationStatus AuthenticationStatus = MfaAuthenticationStatus.Failed,
    string? HandshakeToken = null,
    IEnumerable<string>? RequiredFactors = null,
    string? ErrorMessage = null,
    MfaAuthenticationResult? AuthenticationResult = null);

/// <summary>
/// Represents a registered passkey credential summary.
/// </summary>
/// <param name="Id">The credential id.</param>
/// <param name="CredentialId">The WebAuthn credential identifier.</param>
/// <param name="DisplayName">The passkey display name.</param>
/// <param name="CreatedAt">The creation timestamp.</param>
/// <param name="LastUsedAt">The last used timestamp.</param>
/// <param name="SignCount">The stored signature counter.</param>
/// <param name="Transports">The reported authenticator transports.</param>
public sealed record PasskeyCredentialSummary(
    Guid Id,
    string CredentialId,
    string DisplayName,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt,
    long SignCount,
    string[] Transports);

/// <summary>
/// Stores passkey public metadata and signature counter state in the Ashlar credential record.
/// </summary>
/// <remarks>
/// This metadata contains public credential state needed for future assertions. Raw WebAuthn assertion material,
/// client data JSON, authenticator data, challenges, and ceremony payloads are not stored here.
/// </remarks>
public sealed class PasskeyCredentialMetadata
{
    /// <summary>
    /// Gets or sets the passkey display name.
    /// </summary>
    public string DisplayName { get; set; } = "Passkey";
    /// <summary>
    /// Gets or sets the credential public key used to verify assertions.
    /// </summary>
    public string PublicKey { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the last persisted WebAuthn signature counter used for cloned-authenticator detection.
    /// </summary>
    public long SignCount { get; set; }
    /// <summary>
    /// Gets or sets the authenticator transports.
    /// </summary>
    public string[] Transports { get; set; } = [];
    /// <summary>
    /// Gets or sets the authenticator AAGUID.
    /// </summary>
    public string? Aaguid { get; set; }
    /// <summary>
    /// Gets or sets the authenticator attachment.
    /// </summary>
    public string? AuthenticatorAttachment { get; set; }
    /// <summary>
    /// Gets or sets whether the credential is discoverable.
    /// </summary>
    public bool Discoverable { get; set; } = true;
}

internal static class PasskeyCredentialMetadataOperations
{
    internal static PasskeyCredentialMetadata ReadOrDefault(string? credentialMetadata)
    {
        if (!TryRead(credentialMetadata, out var metadata))
        {
            return new PasskeyCredentialMetadata();
        }

        return metadata;
    }

    internal static bool TryRead(string? credentialMetadata, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out PasskeyCredentialMetadata? metadata)
    {
        metadata = null;
        if (string.IsNullOrWhiteSpace(credentialMetadata))
        {
            return false;
        }

        try
        {
            metadata = JsonSerializer.Deserialize<PasskeyCredentialMetadata>(credentialMetadata, PasskeyJson.Options);
        }
        catch (JsonException)
        {
            return false;
        }

        return metadata != null;
    }

    internal static bool TryUpdateAssertionMetadata(string? credentialMetadata, long signCount, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? updatedMetadata)
    {
        updatedMetadata = null;
        if (signCount < 0 || !TryRead(credentialMetadata, out var metadata))
        {
            return false;
        }

        if (metadata.SignCount < 0 || (metadata.SignCount > 0 && signCount <= metadata.SignCount))
        {
            return false;
        }

        metadata.SignCount = signCount;
        updatedMetadata = JsonSerializer.Serialize(metadata, PasskeyJson.Options);
        return true;
    }
}

/// <summary>
/// Represents a verified passkey registration result.
/// </summary>
/// <param name="CredentialId">The WebAuthn credential id.</param>
/// <param name="PublicKey">The credential public key.</param>
/// <param name="SignCount">The signature counter.</param>
/// <param name="Transports">The reported authenticator transports.</param>
/// <param name="Aaguid">The authenticator AAGUID.</param>
/// <param name="AuthenticatorAttachment">The authenticator attachment mode, such as platform or cross-platform.</param>
/// <param name="Discoverable">Whether the credential is discoverable.</param>
/// <param name="UserVerified">Whether user verification was performed.</param>
public sealed record PasskeyRegistrationVerificationResult(
    string CredentialId,
    string PublicKey,
    long SignCount,
    string[] Transports,
    string? Aaguid = null,
    string? AuthenticatorAttachment = null,
    bool Discoverable = true,
    bool UserVerified = false);

/// <summary>
/// Represents a verified passkey authentication result.
/// </summary>
/// <param name="CredentialId">The WebAuthn credential id.</param>
/// <param name="SignCount">The signature counter.</param>
/// <param name="UserVerified">Whether user verification was performed.</param>
public sealed record PasskeyAuthenticationVerificationResult(
    string CredentialId,
    long SignCount,
    bool UserVerified = false);
