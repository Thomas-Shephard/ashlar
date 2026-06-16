using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator account recovery option lookup.
/// </summary>
/// <param name="UserId">User whose recovery options should be loaded.</param>
/// <param name="Tenant">Requested scope. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across every scope. Cannot be combined with <paramref name="Tenant" />.</param>
/// <param name="RecentSecurityEventWindow">Optional recent security event window for the embedded account-security posture.</param>
public sealed record AccountRecoveryOptionsRequest(
    Guid UserId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false,
    TimeSpan? RecentSecurityEventWindow = null)
{
    /// <summary>
    /// Throws when the account recovery options request is not safe to execute.
    /// </summary>
    /// <param name="request">Recovery options request to validate before querying administrator data.</param>
    public static void ThrowIfInvalid(AccountRecoveryOptionsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.UserId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(request));
        }
    }
}

/// <summary>
/// Display-safe administrator account recovery options for a user account.
/// </summary>
/// <param name="Detail">The target user detail and account-security posture.</param>
/// <param name="Actions">The display-safe destructive action previews.</param>
public sealed record AccountRecoveryOptions(
    UserAdministrationDetail Detail,
    AccountRecoveryActionOptions Actions);

/// <summary>
/// Display-safe destructive action previews for account recovery tooling.
/// </summary>
/// <param name="WouldResetMfa">Whether an MFA reset would remove at least one resettable factor credential or remembered MFA device.</param>
/// <param name="WouldRevokeSessions">Whether session revocation would revoke at least one active session.</param>
/// <param name="RevocableProviderOptions">Display-safe revocable credential provider options.</param>
/// <param name="Warnings">Warnings for destructive operations, such as removing the last primary sign-in method.</param>
public sealed record AccountRecoveryActionOptions(
    bool WouldResetMfa,
    bool WouldRevokeSessions,
    IReadOnlyList<AccountRecoveryProviderOption> RevocableProviderOptions,
    IReadOnlyList<AccountRecoveryWarning> Warnings);

/// <summary>
/// Display-safe credential option that can be revoked by <paramref name="Provider" />.
/// </summary>
/// <param name="Provider">Provider key for revocable credentials.</param>
/// <param name="DisplayName">Display-safe label for <paramref name="Provider" />.</param>
/// <param name="CredentialCount">The number of revocable credentials for this <paramref name="Provider" />.</param>
/// <param name="PrimaryCredentialCount">The number of revocable primary credentials for this <paramref name="Provider" />.</param>
/// <param name="AdditionalVerificationCredentialCount">The number of revocable additional verification credentials for this <paramref name="Provider" />.</param>
/// <param name="WouldRemoveLastPrimarySignInMethod">Whether revoking this <paramref name="Provider" /> may remove the account's last available primary sign-in method.</param>
public sealed record AccountRecoveryProviderOption(
    AuthenticationProviderKey Provider,
    string DisplayName,
    int CredentialCount,
    int PrimaryCredentialCount,
    int AdditionalVerificationCredentialCount,
    bool WouldRemoveLastPrimarySignInMethod);

/// <summary>
/// Display-safe warning for an account recovery option.
/// </summary>
/// <param name="Code">Stable warning code.</param>
/// <param name="Message">Display-safe warning message.</param>
/// <param name="Provider">Optional provider key associated with the warning.</param>
public sealed record AccountRecoveryWarning(
    string Code,
    string Message,
    AuthenticationProviderKey? Provider = null);

/// <summary>
/// Base request for destructive administrator account recovery execution.
/// </summary>
public abstract record AccountRecoveryExecutionRequest
{
    /// <summary>
    /// Initializes destructive account recovery execution metadata and validates that its <paramref name="Tenant" /> scope is explicit.
    /// </summary>
    /// <param name="UserId">User targeted by the destructive recovery operation.</param>
    /// <param name="Audit">Audit metadata recorded with the account recovery execution.</param>
    /// <param name="Tenant">Tenant scope for the target user. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
    /// <param name="Reason">Optional display-safe reason recorded with revocation and security events. Do not include secrets, tokens, or credentials.</param>
    /// <param name="IncludeAllTenants">Whether to remove scope filtering for the specified <paramref name="UserId" />. Cannot be combined with <paramref name="Tenant" />.</param>
    protected AccountRecoveryExecutionRequest(
        Guid UserId,
        AuditContext Audit,
        TenantContext? Tenant = null,
        string? Reason = null,
        bool IncludeAllTenants = false)
    {
        this.UserId = UserId;
        this.Audit = Audit ?? throw new ArgumentNullException(nameof(Audit), "Destructive account recovery execution requires audit metadata.");
        this.Tenant = Tenant;
        this.Reason = Reason;
        this.IncludeAllTenants = IncludeAllTenants;
        ValidateExecutionRequest(UserId, Tenant, IncludeAllTenants);
    }

    /// <summary>User targeted by the destructive recovery operation.</summary>
    public Guid UserId { get; }

    /// <summary>Audit metadata recorded with the account recovery execution.</summary>
    public AuditContext Audit { get; }

    /// <summary>Tenant scope for the target user, or <see langword="null" /> when <see cref="IncludeAllTenants" /> is enabled.</summary>
    public TenantContext? Tenant { get; }

    /// <summary>Optional provider-neutral, display-safe reason recorded with revocation and security events. Do not include secrets, tokens, or credentials.</summary>
    public string? Reason { get; }

    /// <summary>Whether scope filtering is removed for the specified <see cref="UserId" />.</summary>
    public bool IncludeAllTenants { get; }

    /// <summary>
    /// Throws when the request is not safe to execute.
    /// </summary>
    public virtual void ThrowIfInvalid()
    {
        ValidateExecutionRequest(UserId, Tenant, IncludeAllTenants);
    }

    private static void ValidateExecutionRequest(Guid userId, TenantContext? tenant, bool includeAllTenants)
    {
        AdministrationScopeValidation.ThrowIfInvalidScope(tenant, includeAllTenants);
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        }
    }
}

/// <summary>
/// Request for destructive administrator MFA reset execution.
/// </summary>
/// <param name="UserId">User whose MFA recovery state should be reset.</param>
/// <param name="Audit">Audit metadata recorded with the MFA reset.</param>
/// <param name="Tenant">Tenant scope for the target user. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="Reason">Optional provider-neutral, display-safe reason recorded with revocation and security events. Do not include secrets, tokens, or credentials.</param>
/// <param name="IncludeAllTenants">Whether to remove scope filtering for the specified <paramref name="UserId" />. Cannot be combined with <paramref name="Tenant" />.</param>
public sealed record AccountRecoveryResetMfaRequest(
    Guid UserId,
    AuditContext Audit,
    TenantContext? Tenant = null,
    string? Reason = null,
    bool IncludeAllTenants = false)
    : AccountRecoveryExecutionRequest(UserId, Audit, Tenant, Reason, IncludeAllTenants);

/// <summary>
/// Request for destructive administrator session revocation execution.
/// </summary>
/// <param name="UserId">User whose sessions should be revoked.</param>
/// <param name="Audit">Audit metadata recorded with the session revocation.</param>
/// <param name="Tenant">Tenant scope for the target user. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="Reason">Optional provider-neutral, display-safe reason recorded with revocation and security events. Do not include secrets, tokens, or credentials.</param>
/// <param name="IncludeAllTenants">Whether to remove scope filtering for the specified <paramref name="UserId" />. Cannot be combined with <paramref name="Tenant" />.</param>
public sealed record AccountRecoveryRevokeSessionsRequest(
    Guid UserId,
    AuditContext Audit,
    TenantContext? Tenant = null,
    string? Reason = null,
    bool IncludeAllTenants = false)
    : AccountRecoveryExecutionRequest(UserId, Audit, Tenant, Reason, IncludeAllTenants);

/// <summary>
/// Request for destructive administrator provider credential revocation execution.
/// </summary>
public sealed record AccountRecoveryRevokeProviderCredentialsRequest : AccountRecoveryExecutionRequest
{
    /// <summary>
    /// Initializes destructive <paramref name="Provider" /> credential revocation metadata.
    /// </summary>
    /// <param name="UserId">User whose <paramref name="Provider" /> credentials should be revoked.</param>
    /// <param name="Provider">Credential provider key to revoke.</param>
    /// <param name="Audit">Audit metadata recorded with the <paramref name="Provider" /> credential revocation.</param>
    /// <param name="Tenant">Tenant scope for the target user. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
    /// <param name="Reason">Optional display-safe reason recorded with revocation and security events. Do not include secrets, tokens, or credentials.</param>
    /// <param name="IncludeAllTenants">Whether to remove scope filtering for the specified <paramref name="UserId" />. Cannot be combined with <paramref name="Tenant" />.</param>
    public AccountRecoveryRevokeProviderCredentialsRequest(
        Guid UserId,
        AuthenticationProviderKey Provider,
        AuditContext Audit,
        TenantContext? Tenant = null,
        string? Reason = null,
        bool IncludeAllTenants = false)
        : base(UserId, Audit, Tenant, Reason, IncludeAllTenants)
    {
        this.Provider = Provider;
        ValidateProvider(Provider);
    }

    /// <summary>Credential provider key whose credentials should be revoked.</summary>
    public AuthenticationProviderKey Provider { get; }

    /// <inheritdoc />
    public override void ThrowIfInvalid()
    {
        base.ThrowIfInvalid();
        ValidateProvider(Provider);
    }

    private static void ValidateProvider(AuthenticationProviderKey provider)
    {
        if (!provider.IsConfigured)
        {
            throw new ArgumentException("Provider key must be fully initialized with a configured provider type and name.", nameof(provider));
        }

        if (provider.Type == ProviderType.Internal)
        {
            throw new ArgumentException("Internal credential providers are not account recovery revocation targets.", nameof(provider));
        }
    }
}
