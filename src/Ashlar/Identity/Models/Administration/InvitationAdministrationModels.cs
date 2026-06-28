using Ashlar.Auditing;

namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Provider-neutral invitation lifecycle states for administrator filtering and display.
/// </summary>
public enum InvitationAdministrationStatus
{
    /// <summary>The invitation has not been accepted, revoked, or expired.</summary>
    Pending = 0,
    /// <summary>The invitation has been accepted and can no longer be used.</summary>
    Accepted = 1,
    /// <summary>The invitation has been revoked before acceptance.</summary>
    Revoked = 2,
    /// <summary>The invitation expiry time has passed before acceptance or revocation.</summary>
    Expired = 3
}

/// <summary>
/// Request for administrator invitation search.
/// </summary>
/// <remarks>
/// Host applications must authorize callers and apply any required step-up policy before executing this read-only operation.
/// Searches require an explicit <see cref="Tenant" /> scope or <see cref="IncludeAllTenants" /> for intentional cross-tenant operations views.
/// Raw invitation tokens and token hashes are never returned.
/// </remarks>
public sealed record SearchInvitationsRequest
{
    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global invitations; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Whether to search across all tenant scopes. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }

    /// <summary>Optional email fragment matched against the normalized lookup form.</summary>
    public string? EmailQuery { get; init; }

    /// <summary>Optional exact email address matched using the normalized lookup form.</summary>
    public string? Email { get; init; }

    /// <summary>Optional invitation lifecycle state filter.</summary>
    public InvitationAdministrationStatus? Status { get; init; }

    /// <summary>Inclusive lower creation time bound.</summary>
    public DateTimeOffset? CreatedFrom { get; init; }

    /// <summary>Inclusive upper creation time bound.</summary>
    public DateTimeOffset? CreatedTo { get; init; }

    /// <summary>Inclusive lower acceptance time bound.</summary>
    public DateTimeOffset? AcceptedFrom { get; init; }

    /// <summary>Inclusive upper acceptance time bound.</summary>
    public DateTimeOffset? AcceptedTo { get; init; }

    /// <summary>Inclusive lower revocation time bound.</summary>
    public DateTimeOffset? RevokedFrom { get; init; }

    /// <summary>Inclusive upper revocation time bound.</summary>
    public DateTimeOffset? RevokedTo { get; init; }

    /// <summary>Inclusive lower expiration time bound.</summary>
    public DateTimeOffset? ExpiresFrom { get; init; }

    /// <summary>Inclusive upper expiration time bound.</summary>
    public DateTimeOffset? ExpiresTo { get; init; }

    /// <summary>Maximum number of invitations to return.</summary>
    public int Limit { get; init; } = 50;

    /// <summary>Number of invitations to skip.</summary>
    public int Offset { get; init; }

    /// <summary>
    /// Throws when the invitation administration search request is not safe to execute.
    /// </summary>
    /// <param name="request">Search request to validate before querying invitation administration data.</param>
    public static void ThrowIfInvalid(SearchInvitationsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.Limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Limit, "Limit must be greater than zero.");
        }

        if (request.Offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Offset, "Offset cannot be negative.");
        }
    }
}

/// <summary>
/// Display-safe invitation row for administrator search results.
/// </summary>
/// <param name="Id">Stable invitation identifier.</param>
/// <param name="DisplayEmail">Sanitized display/delivery email address on the invitation, returned for administrator display. This is not the normalized lookup form.</param>
/// <param name="TenantId">Tenant scope for the invitation, or <see langword="null" /> for a global invitation.</param>
/// <param name="Status">Current invitation lifecycle state.</param>
/// <param name="CreatedAt">UTC time when the invitation was created.</param>
/// <param name="UpdatedAt">UTC time when the invitation was last updated, when known.</param>
/// <param name="ExpiresAt">UTC time after which the invitation cannot be accepted.</param>
/// <param name="AcceptedAt">UTC time when the invitation was accepted, when applicable.</param>
/// <param name="RevokedAt">UTC time when the invitation was revoked, when applicable.</param>
public sealed record InvitationAdministrationSummary(
    Guid Id,
    string DisplayEmail,
    Guid? TenantId,
    InvitationAdministrationStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset? UpdatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? AcceptedAt,
    DateTimeOffset? RevokedAt);

/// <summary>
/// Paged invitation search result.
/// </summary>
/// <param name="Items">Page of display-safe invitation summaries.</param>
/// <param name="Limit">Maximum page size requested.</param>
/// <param name="Offset">Number of matching invitations skipped before this page.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record InvitationSearchResult(
    IReadOnlyList<InvitationAdministrationSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Request for an administrator invitation single-item lookup.
/// </summary>
/// <param name="InvitationId">Invitation to load.</param>
/// <param name="Tenant">Requested scope. Use <see cref="TenantContext.Global" /> for global invitations; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across all tenancy scopes. Cannot be combined with <paramref name="Tenant" />.</param>
/// <remarks>
/// Host applications must authorize callers and apply any required step-up policy before executing this read-only operation.
/// Raw invitation tokens and token hashes are never returned.
/// </remarks>
public sealed record InvitationAdministrationLookupRequest(
    Guid InvitationId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false)
{
    /// <summary>
    /// Throws when the invitation lookup request is not safe to execute.
    /// </summary>
    /// <param name="request">Lookup request to validate before loading administrator data.</param>
    public static void ThrowIfInvalid(InvitationAdministrationLookupRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.InvitationId == Guid.Empty)
        {
            throw new ArgumentException("Invitation ID cannot be empty.", nameof(request));
        }
    }
}

/// <summary>
/// Request for administrator invitation revocation by identifier.
/// </summary>
/// <param name="InvitationId">Invitation to revoke.</param>
/// <param name="Tenant">Requested scope. Use <see cref="TenantContext.Global" /> for global invitations; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="IncludeAllTenants">Whether to allow revocation across all tenancy scopes. Cannot be combined with <paramref name="Tenant" />.</param>
/// <param name="Audit">Actor and request metadata required for the emitted <paramref name="Audit" /> event context.</param>
/// <param name="Reason">Optional display-safe reason to include in security event properties.</param>
/// <remarks>
/// Host applications must authorize callers and apply any required step-up policy before executing this mutating operation.
/// The operation never returns raw invitation tokens or token hashes.
/// </remarks>
public sealed record RevokeInvitationAdministrationRequest(
    Guid InvitationId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false,
    AuditContext? Audit = null,
    string? Reason = null)
{
    /// <summary>
    /// Throws when the invitation revocation request is not safe to execute.
    /// </summary>
    /// <param name="request">Revocation request to validate before mutating invitation state.</param>
    public static void ThrowIfInvalid(RevokeInvitationAdministrationRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.InvitationId == Guid.Empty)
        {
            throw new ArgumentException("Invitation ID cannot be empty.", nameof(request));
        }

        if (request.Audit == null)
        {
            throw new ArgumentException("Audit metadata is required for invitation revocation.", nameof(request));
        }
    }
}

/// <summary>
/// Stable outcome for an administrator invitation revocation request.
/// </summary>
public enum InvitationAdministrationRevocationStatus
{
    /// <summary>
    /// The pending invitation was revoked by this operation.
    /// </summary>
    Revoked = 0,

    /// <summary>
    /// The invitation had already been accepted and was not revoked.
    /// </summary>
    AlreadyAccepted = 1,

    /// <summary>
    /// The invitation had already been revoked.
    /// </summary>
    AlreadyRevoked = 2,

    /// <summary>
    /// The invitation had already expired and was not revoked.
    /// </summary>
    Expired = 3,

    /// <summary>
    /// The invitation existed in scope, but the repository did not change it.
    /// </summary>
    NotRevoked = 4
}

/// <summary>
/// Result of administrator invitation revocation by identifier.
/// </summary>
/// <param name="InvitationId">Invitation requested for revocation.</param>
/// <param name="TenantId">Tenant scope for the invitation, or <see langword="null" /> for a global invitation.</param>
/// <param name="RevocationStatus">Stable revocation outcome.</param>
/// <param name="Status">Invitation lifecycle state after the operation.</param>
/// <param name="RevokedAt">UTC time when the invitation entered its terminal revocation state, when applicable.</param>
public sealed record RevokeInvitationAdministrationResult(
    Guid InvitationId,
    Guid? TenantId,
    InvitationAdministrationRevocationStatus RevocationStatus,
    InvitationAdministrationStatus Status,
    DateTimeOffset? RevokedAt);
