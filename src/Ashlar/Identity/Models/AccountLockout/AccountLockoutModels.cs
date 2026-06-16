using Ashlar.Auditing;

namespace Ashlar.Identity.Models.AccountLockout;

/// <summary>
/// Configures automatic per-account lockout after failed primary credential verification.
/// </summary>
public sealed class AccountLockoutOptions
{
    /// <summary>
    /// Failed primary-credential attempt threshold that activates automatic lockout.
    /// </summary>
    public int FailureThreshold { get; set; } = 5;

    /// <summary>
    /// Duration applied to newly activated automatic lockouts.
    /// </summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Allows local-password authentication to continue past durable lockout status lookup failures.
    /// Failed-password recording failures still fail authentication; this option only preserves the generic invalid-credential result after logging that the failed attempt was not recorded.
    /// Keep this disabled unless the deployment knowingly prefers sign-in availability over brute-force protection during lockout backend outages.
    /// </summary>
    public bool FailOpenOnBackendFailure { get; set; }

    /// <summary>
    /// Validates account lockout options.
    /// </summary>
    /// <param name="options">The options to validate.</param>
    /// <returns><see langword="true" /> when the options are valid.</returns>
    public static bool Validate(AccountLockoutOptions? options)
    {
        return options is { FailureThreshold: > 0 } && options.LockoutDuration > TimeSpan.Zero;
    }

    /// <summary>
    /// Throws when the account lockout policy values cannot produce a temporary lockout.
    /// </summary>
    /// <param name="failureThreshold">The failed-attempt threshold that activates lockout.</param>
    /// <param name="lockoutDuration">How long a newly activated lockout remains active.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the threshold or duration is not positive.</exception>
    public static void ThrowIfInvalidPolicy(int failureThreshold, TimeSpan lockoutDuration)
    {
        if (failureThreshold <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(failureThreshold), failureThreshold, "Failure threshold must be greater than zero.");
        }

        if (lockoutDuration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lockoutDuration), lockoutDuration, "Lockout duration must be greater than zero.");
        }
    }
}

/// <summary>
/// Durable automatic lockout state for a user and authentication <paramref name="Provider" />.
/// </summary>
/// <param name="UserId">User whose failed primary credential attempts are tracked.</param>
/// <param name="TenantId">Tenant scope for the user, or <see langword="null" /> for global users.</param>
/// <param name="Provider">Authenticator key whose failed attempts are tracked.</param>
/// <param name="FailedAttemptCount">The number of recorded failures in the current lockout window.</param>
/// <param name="FirstFailedAt">The first failure timestamp in the current lockout window.</param>
/// <param name="LastFailedAt">The most recent failure timestamp in the current lockout window.</param>
/// <param name="LockedUntil">The automatic lockout expiry timestamp, when locked.</param>
/// <param name="Version">A repository concurrency token.</param>
public sealed record AccountLockoutRecord(
    Guid UserId,
    Guid? TenantId,
    AuthenticationProviderKey Provider,
    int FailedAttemptCount,
    DateTimeOffset FirstFailedAt,
    DateTimeOffset LastFailedAt,
    DateTimeOffset? LockedUntil,
    string Version);

/// <summary>
/// Result of atomically recording a failed credential verification in durable lockout state.
/// </summary>
/// <param name="Record">Durable lockout record after the failed attempt was applied.</param>
/// <param name="LockoutActivated">Whether this write activated a new automatic lockout.</param>
public sealed record AccountLockoutRecordUpdate(
    AccountLockoutRecord Record,
    bool LockoutActivated);

/// <summary>
/// Current automatic lockout status for a user and <paramref name="Provider" />.
/// </summary>
/// <param name="UserId">User whose automatic lockout status was evaluated.</param>
/// <param name="TenantId">Tenant scope for the user, or <see langword="null" /> for global users.</param>
/// <param name="Provider">Authenticator key whose automatic lockout status was evaluated.</param>
/// <param name="FailedAttemptCount">The number of recorded failures in the current lockout window.</param>
/// <param name="FirstFailedAt">The first failure timestamp in the current lockout window.</param>
/// <param name="LastFailedAt">The most recent failure timestamp in the current lockout window.</param>
/// <param name="LockedUntil">The automatic lockout expiry timestamp, when locked.</param>
/// <param name="IsLockedOut">Whether automatic lockout is active at the time of evaluation.</param>
public sealed record AccountLockoutStatus(
    Guid UserId,
    Guid? TenantId,
    AuthenticationProviderKey Provider,
    int FailedAttemptCount,
    DateTimeOffset? FirstFailedAt,
    DateTimeOffset? LastFailedAt,
    DateTimeOffset? LockedUntil,
    bool IsLockedOut)
{
    /// <summary>
    /// Creates an unlocked empty status.
    /// </summary>
    /// <param name="userId">User whose automatic lockout status is being represented.</param>
    /// <param name="tenantId">Tenant scope for the user, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">Authentication provider key for the credential family being evaluated.</param>
    /// <returns>An unlocked status with no failures.</returns>
    public static AccountLockoutStatus None(Guid userId, Guid? tenantId, AuthenticationProviderKey provider)
    {
        return new AccountLockoutStatus(userId, tenantId, provider, 0, null, null, null, false);
    }
}

/// <summary>
/// Result of recording a failed credential verification.
/// </summary>
/// <param name="Status">Automatic lockout status after the failed attempt was applied.</param>
/// <param name="ThresholdReached">Whether the updated failure count meets or exceeds the configured threshold.</param>
/// <param name="LockoutActivated">Whether this failure activated a new automatic lockout.</param>
public sealed record AccountLockoutFailureResult(
    AccountLockoutStatus Status,
    bool ThresholdReached,
    bool LockoutActivated);

/// <summary>
/// Safe context attached to account lockout operations and security events.
/// </summary>
/// <param name="Audit">Optional safe operation metadata.</param>
/// <param name="Tenant">Optional tenant scope that must match the user.</param>
public sealed record AccountLockoutContext(
    AuditContext? Audit = null,
    TenantContext? Tenant = null);

/// <summary>
/// Request for administrator account lockout search.
/// </summary>
public sealed record SearchAccountLockoutsRequest
{
    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Whether to search across all tenant scopes. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }

    /// <summary>Optional user filter.</summary>
    public Guid? UserId { get; init; }

    /// <summary>Optional authentication provider filter.</summary>
    public AuthenticationProviderKey? Provider { get; init; }

    /// <summary>Optional active lockout filter evaluated with the service clock.</summary>
    public bool? LockedOut { get; init; }

    /// <summary>Maximum number of lockout records to return.</summary>
    public int Limit { get; init; } = 50;

    /// <summary>Number of lockout records to skip.</summary>
    public int Offset { get; init; }

    /// <summary>
    /// Throws when the account lockout search request is not safe to execute.
    /// </summary>
    /// <param name="request">The search request to validate.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="request" /> is <see langword="null" />.</exception>
    /// <exception cref="ArgumentException">Thrown when the tenant scope, user identifier, or provider filter is invalid.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when paging values are invalid.</exception>
    public static void ThrowIfInvalid(SearchAccountLockoutsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Limit < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Limit, "Limit must be greater than zero.");
        }

        if (request.Offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Offset, "Offset cannot be negative.");
        }

        if (request is { Tenant: null, IncludeAllTenants: false })
        {
            throw new ArgumentException("Tenant scope must be explicit.", nameof(request));
        }

        if (request is { Tenant: not null, IncludeAllTenants: true })
        {
            throw new ArgumentException("Tenant scope cannot be combined with all-tenant search.", nameof(request));
        }

        if (request.UserId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(request));
        }

        if (request.Provider is { IsConfigured: false })
        {
            throw new ArgumentException("Provider key must be fully initialized with a configured provider type and name.", nameof(request));
        }
    }
}

/// <summary>
/// Safe administrator summary of automatic account lockout state.
/// </summary>
/// <param name="UserId">User whose automatic lockout status is shown.</param>
/// <param name="TenantId">Tenant scope for the user, or <see langword="null" /> for a global user.</param>
/// <param name="Provider">Authenticator key shown in the administrator summary.</param>
/// <param name="FailedAttemptCount">The number of recorded failures in the current lockout window.</param>
/// <param name="FirstFailedAt">The first failure timestamp in the current lockout window.</param>
/// <param name="LastFailedAt">The most recent failure timestamp in the current lockout window.</param>
/// <param name="LockedUntil">The automatic lockout expiry timestamp, when locked.</param>
/// <param name="IsLockedOut">Whether automatic lockout is active at the time of evaluation.</param>
public sealed record AccountLockoutAdministrationSummary(
    Guid UserId,
    Guid? TenantId,
    AuthenticationProviderKey Provider,
    int FailedAttemptCount,
    DateTimeOffset FirstFailedAt,
    DateTimeOffset LastFailedAt,
    DateTimeOffset? LockedUntil,
    bool IsLockedOut);

/// <summary>
/// Paged account lockout search result.
/// </summary>
/// <param name="Items">Lockout summaries returned for the requested page.</param>
/// <param name="Limit">The effective page size.</param>
/// <param name="Offset">The number of skipped records.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record AccountLockoutSearchResult(
    IReadOnlyList<AccountLockoutAdministrationSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Request for administrator account lockout status.
/// </summary>
/// <param name="Tenant">Explicit tenant scope. Use <see cref="TenantContext.Global" /> for global users.</param>
public sealed record AccountLockoutAdministrationRequest(TenantContext Tenant);

/// <summary>
/// Request for administrator account lockout reset.
/// </summary>
/// <param name="Tenant">Explicit tenant scope. Use <see cref="TenantContext.Global" /> for global users.</param>
/// <param name="Audit">Required safe audit metadata describing who requested reset.</param>
/// <param name="Reason">Optional provider-neutral, display-safe reason recorded with the reset event. Do not include secrets, tokens, or credentials. Cannot exceed 512 characters.</param>
public sealed record ResetAccountLockoutRequest
{
    /// <summary>
    /// Initializes administrator account lockout reset metadata.
    /// </summary>
    /// <param name="Tenant">Explicit tenant scope. Use <see cref="TenantContext.Global" /> for global users.</param>
    /// <param name="Audit">Required safe audit metadata describing who requested reset.</param>
    /// <param name="Reason">Optional provider-neutral, display-safe reason recorded with the reset event. Do not include secrets, tokens, or credentials. Cannot exceed 512 characters.</param>
    public ResetAccountLockoutRequest(TenantContext Tenant, AuditContext Audit, string? Reason = null)
    {
        this.Tenant = Tenant;
        this.Audit = Audit ?? throw new ArgumentNullException(nameof(Audit), "Admin account lockout reset requires audit metadata.");
        this.Reason = Reason;
    }

    /// <summary>Explicit tenant scope. Use <see cref="TenantContext.Global" /> for global users.</summary>
    public TenantContext Tenant { get; init; }

    /// <summary>Required safe audit metadata describing who requested the reset.</summary>
    public AuditContext Audit { get; }

    /// <summary>Optional provider-neutral, display-safe reason recorded with the reset event. Do not include secrets, tokens, or credentials.</summary>
    public string? Reason { get; init; }
}
