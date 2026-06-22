namespace Ashlar.Operational.Configuration;

/// <summary>
/// Stable Ashlar configuration validation issue codes.
/// </summary>
public static class AshlarConfigurationIssueCodes
{
    /// <summary>
    /// The user repository is not configured.
    /// </summary>
    public const string UserRepositoryMissing = "ASHLAR-CONFIG-USER-REPOSITORY-MISSING";

    /// <summary>
    /// The credential repository is not configured.
    /// </summary>
    public const string CredentialRepositoryMissing = "ASHLAR-CONFIG-CREDENTIAL-REPOSITORY-MISSING";

    /// <summary>
    /// The secret protector is not configured.
    /// </summary>
    public const string SecretProtectorMissing = "ASHLAR-CONFIG-SECRET-PROTECTOR-MISSING";

    /// <summary>
    /// The authentication session repository is not configured.
    /// </summary>
    public const string AuthenticationSessionRepositoryMissing = "ASHLAR-CONFIG-AUTHENTICATION-SESSION-REPOSITORY-MISSING";

    /// <summary>
    /// The user administration repository is not configured.
    /// </summary>
    public const string UserAdministrationRepositoryMissing = "ASHLAR-CONFIG-USER-ADMINISTRATION-REPOSITORY-MISSING";

    /// <summary>
    /// The credential administration repository is not configured.
    /// </summary>
    public const string CredentialAdministrationRepositoryMissing = "ASHLAR-CONFIG-CREDENTIAL-ADMINISTRATION-REPOSITORY-MISSING";

    /// <summary>
    /// The security event administration repository is not configured.
    /// </summary>
    public const string SecurityEventAdministrationRepositoryMissing = "ASHLAR-CONFIG-SECURITY-EVENT-ADMINISTRATION-REPOSITORY-MISSING";

    /// <summary>
    /// The authentication session administration repository is not configured.
    /// </summary>
    public const string AuthenticationSessionAdministrationRepositoryMissing = "ASHLAR-CONFIG-AUTHENTICATION-SESSION-ADMINISTRATION-REPOSITORY-MISSING";

    /// <summary>
    /// The invitation repository is not configured.
    /// </summary>
    public const string InvitationRepositoryMissing = "ASHLAR-CONFIG-INVITATION-REPOSITORY-MISSING";

    /// <summary>
    /// The bootstrap state repository is not configured.
    /// </summary>
    public const string BootstrapStateRepositoryMissing = "ASHLAR-CONFIG-BOOTSTRAP-STATE-REPOSITORY-MISSING";

    /// <summary>
    /// Bootstrap options are invalid.
    /// </summary>
    public const string BootstrapOptionsInvalid = "ASHLAR-CONFIG-BOOTSTRAP-OPTIONS-INVALID";

    /// <summary>
    /// Bootstrap setup authorization is not configured.
    /// </summary>
    public const string BootstrapSetupAuthorizationMissing = "ASHLAR-CONFIG-BOOTSTRAP-SETUP-AUTHORIZATION-MISSING";

    /// <summary>
    /// Bootstrap grants are configured but authorization services are not configured.
    /// </summary>
    public const string BootstrapGrantServiceMissing = "ASHLAR-CONFIG-BOOTSTRAP-GRANT-SERVICE-MISSING";

    /// <summary>
    /// The authentication handshake repository is not configured.
    /// </summary>
    public const string AuthenticationHandshakeRepositoryMissing = "ASHLAR-CONFIG-AUTHENTICATION-HANDSHAKE-REPOSITORY-MISSING";

    /// <summary>
    /// The authorization grant repository is not configured.
    /// </summary>
    public const string AuthorizationGrantRepositoryMissing = "ASHLAR-CONFIG-AUTHORIZATION-GRANT-REPOSITORY-MISSING";

    /// <summary>
    /// The passkey challenge repository is not configured.
    /// </summary>
    public const string PasskeyChallengeRepositoryMissing = "ASHLAR-CONFIG-PASSKEY-CHALLENGE-REPOSITORY-MISSING";

    /// <summary>
    /// Email delivery is not configured for registered email-based features.
    /// </summary>
    public const string EmailSenderNotConfigured = "ASHLAR-CONFIG-EMAIL-SENDER-NOT-CONFIGURED";

    /// <summary>
    /// Callback URI validation is required but no callback URI allow-list is configured.
    /// </summary>
    public const string CallbackUriAllowListMissing = "ASHLAR-CONFIG-CALLBACK-URI-ALLOWLIST-MISSING";

    /// <summary>
    /// A callback URI allow-list entry is structurally invalid.
    /// </summary>
    public const string CallbackUriAllowListInvalidEntry = "ASHLAR-CONFIG-CALLBACK-URI-ALLOWLIST-INVALID-ENTRY";

    /// <summary>
    /// A callback URI allow-list entry uses HTTP instead of HTTPS.
    /// </summary>
    public const string CallbackUriAllowListInsecureScheme = "ASHLAR-CONFIG-CALLBACK-URI-ALLOWLIST-INSECURE-SCHEME";

    /// <summary>
    /// A callback URI allow-list entry targets a local, private, link-local, multicast, or unspecified host.
    /// </summary>
    public const string CallbackUriAllowListLocalAddress = "ASHLAR-CONFIG-CALLBACK-URI-ALLOWLIST-LOCAL-ADDRESS";

    /// <summary>
    /// Security event auditing is configured with the <see langword="null" /> sink.
    /// </summary>
    public const string NullSecurityEventSink = "ASHLAR-CONFIG-NULL-SECURITY-EVENT-SINK";

    /// <summary>
    /// Account security operations are configured with Ashlar's permissive guard.
    /// </summary>
    public const string PermissiveAccountSecurityGuard = "ASHLAR-CONFIG-PERMISSIVE-ACCOUNT-SECURITY-GUARD";

    /// <summary>
    /// Authentication rate limiting is configured with the in-memory implementation.
    /// </summary>
    public const string InMemoryAuthenticationRateLimiter = "ASHLAR-CONFIG-IN-MEMORY-RATE-LIMITER";

    /// <summary>
    /// Security notification suppression is configured with the in-memory implementation.
    /// </summary>
    public const string InMemorySecurityNotificationSuppressionStore = "ASHLAR-CONFIG-IN-MEMORY-SECURITY-NOTIFICATION-SUPPRESSION";

    /// <summary>
    /// Transactions are configured with the <see langword="null" /> transaction provider.
    /// </summary>
    public const string NullTransactionProvider = "ASHLAR-CONFIG-NULL-TRANSACTION-PROVIDER";
}
