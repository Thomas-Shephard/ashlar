namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Represents an authentication provider that can identify users and validate provider assertions.
/// </summary>
public interface IAuthenticationProvider
{
    /// <summary>
    /// Canonical identity for this provider implementation.
    /// </summary>
    AuthenticationProviderKey Key { get; }

    /// <summary>
    /// Whether credentials managed by this provider should be encrypted by the identity service.
    /// Defaults to <c><see langword="true" /></c>.
    /// </summary>
    bool ProtectsCredentials => true;

    /// <summary>
    /// Typical credential length used for timing-safe dummy values.
    /// </summary>
    int TypicalCredentialLength => 256;

    /// <summary>
    /// Derives the provider-specific credential key for a user.
    /// </summary>
    /// <param name="assertion">Provider-supplied assertion used to derive the credential key. Treat as sensitive unless the provider documents otherwise.</param>
    /// <param name="userId">The user that will own the credential.</param>
    /// <returns>Provider-specific credential key used for lookup and storage.</returns>
    string GetProviderKey(IAuthenticationAssertion assertion, Guid userId);

    /// <summary>
    /// Prepares a raw credential value for storage.
    /// </summary>
    /// <param name="assertion">Provider-supplied assertion associated with the raw credential value.</param>
    /// <param name="rawValue">The raw credential value before provider-specific preparation. Treat this value as sensitive.</param>
    /// <returns>The provider-prepared credential value to store, or <see langword="null" /> when no value should be stored.</returns>
    string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue);

    /// <summary>
    /// Attempts to resolve the user associated with the given assertion.
    /// </summary>
    /// <param name="assertion">Provider-supplied assertion used to identify the user. Treat as sensitive unless the provider documents otherwise.</param>
    /// <param name="context">Tenant, audit, and request metadata for the authentication attempt.</param>
    /// <param name="repository">The user repository.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The matching user, or <see langword="null" /> when the assertion does not identify a user.</returns>
    Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IUserRepository repository, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates an assertion against the resolved provider credential.
    /// </summary>
    /// <param name="assertion">Provider-supplied credential or factor assertion to verify.</param>
    /// <param name="credential">The credential resolved for the assertion, when one exists.</param>
    /// <param name="cancellationToken">A token that can cancel authentication.</param>
    /// <returns>The provider authentication status, claims, and any credential update or consumption requirement. This result does not issue an application session.</returns>
    Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves the credential associated with the given assertion and user.
    /// </summary>
    /// <param name="userId">The user that must own the credential.</param>
    /// <param name="assertion">Provider-supplied assertion used to locate the credential. Treat as sensitive unless the provider documents otherwise.</param>
    /// <param name="context">Tenant, audit, and request metadata for the authentication attempt, when available.</param>
    /// <param name="repository">The credential repository.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>The matching credential, or <see langword="null" /> when the provider uses the default lookup.</returns>
    Task<UserCredential?> ResolveCredentialAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        AuthenticationContext? context,
        ICredentialRepository repository,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult<UserCredential?>(null);
    }
}

/// <summary>
/// Marks an authentication provider that can verify a primary sign-in credential.
/// </summary>
public interface IPrimaryAuthenticationProvider : IAuthenticationProvider;

/// <summary>
/// Marks an authentication provider that can verify a secondary MFA or step-up factor.
/// </summary>
public interface ISecondaryAuthenticationFactorProvider : IAuthenticationProvider
{
    /// <summary>
    /// Normalized factor family represented by this provider.
    /// </summary>
    string FactorType { get; }

    /// <summary>
    /// Determines whether this provider can satisfy a pending authentication factor.
    /// </summary>
    /// <param name="factorType">Additional-verification factor family required by the pending challenge.</param>
    /// <returns><see langword="true" /> when this provider can directly satisfy the required factor.</returns>
    bool CanSatisfyFactor(string factorType);
}

/// <summary>
/// Marks a secondary factor provider that may stand in for other pending MFA or step-up factors.
/// </summary>
public interface IBackupAuthenticationFactorProvider : ISecondaryAuthenticationFactorProvider
{
    /// <summary>
    /// Determines whether this backup provider may satisfy the required factor.
    /// </summary>
    /// <param name="requiredFactorType">Additional-verification factor family currently required by the pending challenge.</param>
    /// <returns><see langword="true" /> when this provider may be used as a backup for the required factor.</returns>
    bool CanSatisfyBackupFactor(string requiredFactorType);
}

/// <summary>
/// Represents the result of an authentication attempt.
/// </summary>
/// <param name="Status">Outcome of the authentication attempt.</param>
/// <param name="Claims">Claims produced by the provider.</param>
/// <param name="NewCredentialValue">A replacement credential value to persist after successful authentication.</param>
/// <param name="NewMetadata">Replacement credential metadata to persist after successful authentication.</param>
/// <param name="IsCredentialConsumed">Whether the credential should be consumed after successful authentication.</param>
/// <param name="CredentialUpdateRequirement">Whether credential update failures should fail authentication.</param>
public sealed record AuthenticationResult(
    AuthenticationResultStatus Status,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? Claims = null,
    string? NewCredentialValue = null,
    string? NewMetadata = null,
    bool IsCredentialConsumed = false,
    CredentialUpdateRequirement CredentialUpdateRequirement = CredentialUpdateRequirement.BestEffort)
{
    /// <summary>
    /// Initializes an authentication result from single-value provider claims.
    /// </summary>
    /// <param name="status">The outcome of the authentication attempt.</param>
    /// <param name="claims">The single-value claims.</param>
    /// <param name="newCredentialValue">A replacement credential value to persist after successful authentication.</param>
    /// <param name="newMetadata">Replacement credential metadata to persist after successful authentication.</param>
    /// <param name="isCredentialConsumed">Whether the credential should be consumed after successful authentication.</param>
    /// <param name="credentialUpdateRequirement">Whether credential update failures should fail authentication.</param>
    public AuthenticationResult(
        AuthenticationResultStatus status,
        IDictionary<string, string>? claims,
        string? newCredentialValue = null,
        string? newMetadata = null,
        bool isCredentialConsumed = false,
        CredentialUpdateRequirement credentialUpdateRequirement = CredentialUpdateRequirement.BestEffort)
        : this(
            status,
            AuthenticationClaims.FromSingleValues(claims),
            newCredentialValue,
            newMetadata,
            isCredentialConsumed,
            credentialUpdateRequirement)
    {
    }
}

/// <summary>
/// Represents the outcome of an authentication attempt.
/// </summary>
public enum AuthenticationResultStatus
{
    /// <summary>
    /// Authentication failed.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Authentication succeeded without credential changes.
    /// </summary>
    Succeeded = 1,
    /// <summary>
    /// Authentication succeeded and returned a credential update to persist.
    /// </summary>
    SucceededWithCredentialUpdate = 2,
    /// <summary>
    /// Authentication requires MFA before a session is issued.
    /// </summary>
    MfaRequired = 3
}

/// <summary>
/// Defines the requirement level for persisting credential updates.
/// </summary>
public enum CredentialUpdateRequirement
{
    /// <summary>
    /// The update is best-effort. Failure to persist the update will not fail the authentication.
    /// </summary>
    BestEffort = 0,

    /// <summary>
    /// The update is security-critical. Failure to persist the update will fail the authentication.
    /// </summary>
    Required = 1
}
