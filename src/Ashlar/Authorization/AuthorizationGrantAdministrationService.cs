using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Auditing;

namespace Ashlar.Authorization;

/// <summary>
/// Implements read-only administrator authorization grant search and single-item lookup operations.
/// </summary>
/// <param name="repository">Repository used for safe administrator grant lookup.</param>
/// <param name="options">Validation limits for grant fields.</param>
/// <param name="timeProvider">Clock used for status projection.</param>
/// <param name="authorizationContext">Required host authorizer and active-session store.</param>
/// <remarks>
/// Operations fail closed unless the actor has a valid purpose-bound proof from an active session, matching audit identity,
/// explicit scope, and host authorization for the complete read operation.
/// </remarks>
public sealed class AuthorizationGrantAdministrationService(
    IAuthorizationGrantAdministrationRepository repository,
    AuthorizationGrantOptions? options = null,
    TimeProvider? timeProvider = null,
    AuthorizationGrantMutationContext? authorizationContext = null)
    : IAuthorizationGrantAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IAuthorizationGrantAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly AuthorizationGrantOptions _options = ValidateOptions(options ?? new AuthorizationGrantOptions());
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly IAccountSecurityOperationAuthorizer? _authorizer = authorizationContext?.Authorizer;
    private readonly ActiveSessionFreshProofValidator? _proofValidator = authorizationContext?.SessionRepository is { } sessions
        ? new ActiveSessionFreshProofValidator(sessions, timeProvider ?? TimeProvider.System) : null;

    /// <inheritdoc />
    public async Task<Result<AuthorizationGrantSearchResult>> SearchAuthorizationGrantsAsync(SearchAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateSearchRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (request.Offset < 0)
        {
            return Result.Failure<AuthorizationGrantSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        }

        if (request.Limit < 1)
        {
            return Result.Failure<AuthorizationGrantSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        }

        if (!await IsVerifiedActorAsync(request.Actor, request.Audit, cancellationToken)
            || !await AuthorizeAsync(request.Actor!, request.Tenant, request.IncludeAllTenants,
                request.UserId ?? Guid.Empty, AccountSecurityOperation.SearchAuthorizationGrants, cancellationToken))
            return Result.Failure<AuthorizationGrantSearchResult>(AshlarFailureCodes.ValidationError);

        SearchAuthorizationGrantsRequest repositoryRequest;
        try
        {
            repositoryRequest = Normalize(request) with
            {
                Actor = null,
                Audit = null,
                Limit = Math.Min(request.Limit, MaximumLimit) + 1
            };
            if (repositoryRequest.Role != null && repositoryRequest.Permission != null)
            {
                return Result.Failure<AuthorizationGrantSearchResult>(AshlarFailureCodes.ValidationError, "Role and permission filters cannot be combined.");
            }
        }
        catch (ArgumentException exception)
        {
            return Result.Failure<AuthorizationGrantSearchResult>(AshlarFailureCodes.ValidationError, exception.Message);
        }

        var limit = Math.Min(request.Limit, MaximumLimit);
        var grants = await _repository.SearchAuthorizationGrantsAsync(repositoryRequest, _timeProvider.GetUtcNow(), cancellationToken);
        var hasMore = grants.Count > limit;
        var page = grants.Take(limit).ToList().AsReadOnly();

        return Result.Success(new AuthorizationGrantSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<AuthorizationGrantAdministrationSummary>> GetAuthorizationGrantAsync(AuthorizationGrantAdministrationLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateLookupRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (!await IsVerifiedActorAsync(request.Actor, request.Audit, cancellationToken))
            return Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.ValidationError);
        if (!await AuthorizeAsync(request.Actor!, request.Tenant, request.IncludeAllTenants,
                Guid.Empty, AccountSecurityOperation.ReadAuthorizationGrant, cancellationToken))
            return Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.ValidationError);

        var grant = await _repository.GetAuthorizationGrantAsync(request with { Actor = null, Audit = null },
            _timeProvider.GetUtcNow(), cancellationToken);
        if (grant is null)
            return Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.AuthorizationGrantNotFound, "Authorization grant was not found.");
        if (!await AuthorizeAsync(request.Actor!, request.Tenant, request.IncludeAllTenants,
                grant.UserId, AccountSecurityOperation.ReadAuthorizationGrant, cancellationToken))
            return Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.ValidationError);

        return !request.IncludeAllTenants && !AdministrationScopeValidation.IncludesTenant(request.Tenant!, grant.TenantId)
            ? Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.AuthorizationGrantNotFound, "Authorization grant was not found.")
            : Result.Success(grant);
    }

    /// <summary>
    /// Derives an administrator display status from expiry and revocation timestamps.
    /// </summary>
    /// <param name="expiresAt">UTC expiry time, when configured.</param>
    /// <param name="revokedAt">UTC revocation time, when the grant has been revoked.</param>
    /// <param name="now">UTC time used for expiry evaluation.</param>
    /// <returns>The lifecycle status represented by the supplied timestamps.</returns>
    public static AuthorizationGrantAdministrationStatus DeriveStatus(DateTimeOffset? expiresAt, DateTimeOffset? revokedAt, DateTimeOffset now)
    {
        if (revokedAt != null)
        {
            return AuthorizationGrantAdministrationStatus.Revoked;
        }

        return expiresAt <= now ? AuthorizationGrantAdministrationStatus.Expired : AuthorizationGrantAdministrationStatus.Active;
    }

    private SearchAuthorizationGrantsRequest Normalize(SearchAuthorizationGrantsRequest request)
    {
        return request with
        {
            Role = AuthorizationGrantService.NormalizeOptional(request.Role, nameof(request.Role), _options.MaxRoleLength),
            Permission = AuthorizationGrantService.NormalizeOptional(request.Permission, nameof(request.Permission), _options.MaxPermissionLength),
            ScopeType = AuthorizationGrantService.NormalizeOptional(request.ScopeType, nameof(request.ScopeType), _options.MaxScopeTypeLength),
            ScopeId = AuthorizationGrantService.NormalizeOptional(request.ScopeId, nameof(request.ScopeId), _options.MaxScopeIdLength)
        };
    }

    private static bool TryValidateSearchRequest(SearchAuthorizationGrantsRequest request, out Result<AuthorizationGrantSearchResult> failure)
    {
        try
        {
            SearchAuthorizationGrantsRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthorizationGrantSearchResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool TryValidateLookupRequest(AuthorizationGrantAdministrationLookupRequest request, out Result<AuthorizationGrantAdministrationSummary> failure)
    {
        try
        {
            AuthorizationGrantAdministrationLookupRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static AuthorizationGrantOptions ValidateOptions(AuthorizationGrantOptions options)
    {
        if (!AuthorizationGrantOptions.Validate(options))
        {
            throw new ArgumentException("Authorization grant options are invalid.", nameof(options));
        }

        return options;
    }

    private async ValueTask<bool> IsVerifiedActorAsync(AccountSecurityActorContext? actor, AuditContext? audit,
        CancellationToken cancellationToken)
    {
        if (actor is null) return false;
        if (audit is null) return false;
        if (audit.ActorUserId != actor.ActorUserId) return false;
        if (_proofValidator is null) return false;
        var proofFailure = await _proofValidator.ValidateAsync(actor.ActorUserId, actor.ActorTenant, actor.FreshMfaProof,
            actor.CurrentSessionId, AuthorizationGrantService.AdministrationProofPurpose, cancellationToken);
        return proofFailure is null;
    }

    private ValueTask<bool> AuthorizeAsync(AccountSecurityActorContext actor, TenantContext? tenant,
        bool allTenants, Guid targetUserId, AccountSecurityOperation operation, CancellationToken cancellationToken)
    {
        if (_authorizer is null) return ValueTask.FromResult(false);
        return _authorizer.AuthorizeAsync(new AccountSecurityAuthorizationContext(
            actor.ActorUserId, actor.ActorTenant, targetUserId, tenant, allTenants, operation,
            CurrentSessionId: actor.CurrentSessionId), cancellationToken);
    }
}
