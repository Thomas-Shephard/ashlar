namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Describes the additional verification freshness required for a sensitive action.
/// </summary>
/// <param name="FreshnessWindow">Maximum age of an additional-verification ceremony that may satisfy step-up.</param>
/// <param name="AllowedProviders">Provider keys that may satisfy the step-up requirement, or <see langword="null" /> to allow any.</param>
/// <param name="AllowedFactors">Provider-neutral factor families that may satisfy the step-up requirement, or <see langword="null" /> to allow any.</param>
public sealed record StepUpRequirement(
    TimeSpan FreshnessWindow,
    IReadOnlyCollection<AuthenticationProviderKey>? AllowedProviders = null,
    IReadOnlyCollection<string>? AllowedFactors = null);

/// <summary>
/// Describes a step-up evaluation request.
/// </summary>
/// <param name="Session">Ashlar-validated session capability whose additional-verification metadata is evaluated.</param>
/// <param name="Requirement">Freshness and provider restrictions for the sensitive action.</param>
public sealed record StepUpEvaluationRequest(ValidatedAuthenticationSession? Session, StepUpRequirement Requirement);

/// <summary>
/// Describes the result of a step-up freshness evaluation.
/// </summary>
/// <param name="Succeeded">Whether the requirement was satisfied.</param>
/// <param name="FailureCode">Stable failure identifier when evaluation failed.</param>
/// <param name="FailureReason">Display-safe explanation when evaluation failed.</param>
public sealed record StepUpEvaluationResult(bool Succeeded, AshlarFailureCode? FailureCode = null, string? FailureReason = null)
{
    /// <summary>
    /// Gets a successful evaluation result.
    /// </summary>
    public static StepUpEvaluationResult Success { get; } = new(true);
}

/// <summary>
/// Capability proving that Ashlar validated recent additional verification for a specific active session.
/// </summary>
/// <remarks>
/// Hosts obtain this proof from <see cref="Ashlar.Identity.Features.Mfa.StepUpAuthenticationService.CreateFreshMfaProof" />
/// using session state produced by Ashlar's successful bearer-token validation path.
/// It proves recent MFA by the user that owns the tenant-bound session. Services must separately authorize
/// whether that actor may mutate their own account or a different target account.
/// Revoking or expiring the source session immediately invalidates every outstanding proof minted from it.
/// </remarks>
public sealed class FreshMfaVerificationProof
{
    internal FreshMfaVerificationProof(Guid userId, Guid? tenantId, Guid sessionId, DateTimeOffset verifiedAt, DateTimeOffset expiresAt, string purpose)
    {
        UserId = userId;
        TenantId = tenantId;
        SessionId = sessionId;
        VerifiedAt = verifiedAt;
        ExpiresAt = expiresAt;
        Purpose = purpose;
    }

    /// <summary>User that owns the freshly verified session.</summary>
    public Guid UserId { get; }

    /// <summary>Tenant that bounds the freshly verified session, or <see langword="null" /> for a global session.</summary>
    public Guid? TenantId { get; }

    /// <summary>Session that satisfied the freshness requirement.</summary>
    public Guid SessionId { get; }

    /// <summary>UTC time when additional verification was recorded on the session.</summary>
    public DateTimeOffset VerifiedAt { get; }

    /// <summary>UTC time after which this proof or its source session is no longer valid, whichever occurs first.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>Operation purpose this proof was minted for.</summary>
    public string Purpose { get; }
}

/// <summary>
/// Capability proving that Ashlar validated recent primary authentication for a specific active session.
/// </summary>
/// <remarks>
/// Hosts obtain this proof from <see cref="Ashlar.Identity.Features.Mfa.StepUpAuthenticationService.CreateFreshPrimaryAuthenticationProof" />
/// using session state produced by Ashlar's successful bearer-token validation path. It is intended for bootstrapping the first additional-verification
/// factor, such as initial TOTP enrollment when no usable MFA factor exists yet. It is not accepted for replacing or
/// disabling existing MFA factors or managing recovery codes.
/// Revoking or expiring the source session immediately invalidates every outstanding proof minted from it.
/// </remarks>
public sealed class FreshPrimaryAuthenticationProof
{
    internal FreshPrimaryAuthenticationProof(Guid userId, Guid? tenantId, Guid sessionId, DateTimeOffset authenticatedAt, DateTimeOffset expiresAt, string purpose)
    {
        UserId = userId;
        TenantId = tenantId;
        SessionId = sessionId;
        AuthenticatedAt = authenticatedAt;
        ExpiresAt = expiresAt;
        Purpose = purpose;
    }

    /// <summary>User that owns the freshly authenticated session.</summary>
    public Guid UserId { get; }

    /// <summary>Tenant that bounds the freshly authenticated session, or <see langword="null" /> for a global session.</summary>
    public Guid? TenantId { get; }

    /// <summary>Session that satisfied the freshness requirement.</summary>
    public Guid SessionId { get; }

    /// <summary>UTC time when primary authentication was recorded on the session.</summary>
    public DateTimeOffset AuthenticatedAt { get; }

    /// <summary>UTC time after which this proof or its source session is no longer valid, whichever occurs first.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>Operation purpose this proof was minted for.</summary>
    public string Purpose { get; }
}
