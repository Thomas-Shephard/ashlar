using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Auditing;

namespace Ashlar.Authorization;

internal sealed class AuthorizationGrantAdministrationService(
    IAuthorizationGrantAdministrationRepository repository,
    IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink,
    AuthorizationGrantOptions? options = null,
    TimeProvider? timeProvider = null)
    : IAuthorizationGrantAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IAuthorizationGrantAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly AuthorizationGrantOptions _options = ValidateOptions(options ?? new AuthorizationGrantOptions());
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly AccountSecurityOperationBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

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

        SearchAuthorizationGrantsRequest repositoryRequest;
        try
        {
            repositoryRequest = Normalize(request) with
            {
                Actor = null,
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

        if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                request.UserId ?? Guid.Empty, AccountSecurityOperation.SearchAuthorizationGrants, cancellationToken))
            return Result.Failure<AuthorizationGrantSearchResult>(AshlarFailureCodes.ValidationError);

        var limit = Math.Min(request.Limit, MaximumLimit);
        List<AuthorizationGrantAdministrationSummary> grants;
        try
        {
            grants = (await _repository.SearchAuthorizationGrantsAsync(repositoryRequest, _timeProvider.GetUtcNow(), cancellationToken)).ToList();
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAuthorizationGrants);
            throw;
        }
        if (grants.Any(grant => !AdministrationScopeValidation.IncludesResult(
                request.Tenant, request.IncludeAllTenants, grant.TenantId, request.UserId, grant.UserId)))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAuthorizationGrants);
            throw new InvalidOperationException("The authorization grant administration provider returned a result outside the authorized scope.");
        }
        await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchAuthorizationGrants);
        var hasMore = grants.Count > limit;
        var page = grants.Take(limit).ToList().AsReadOnly();

        return Result.Success(new AuthorizationGrantSearchResult(page, limit, request.Offset, hasMore));
    }

    public async Task<Result<AuthorizationGrantAdministrationSummary>> GetAuthorizationGrantAsync(AuthorizationGrantAdministrationLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateLookupRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                Guid.Empty, AccountSecurityOperation.ReadAuthorizationGrant, cancellationToken))
            return Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.ValidationError);

        AuthorizationGrantAdministrationSummary? grant;
        try
        {
            grant = await _repository.GetAuthorizationGrantAsync(request with { Actor = null },
                _timeProvider.GetUtcNow(), cancellationToken);
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadAuthorizationGrant);
            throw;
        }
        if (grant is null)
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadAuthorizationGrant);
            return Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.AuthorizationGrantNotFound, "Authorization grant was not found.");
        }
        if (grant.Id != request.GrantId
            || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, grant.TenantId))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadAuthorizationGrant);
            return Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.AuthorizationGrantNotFound, "Authorization grant was not found.");
        }
        if (!await _boundary.AuthorizeAsync(request.Actor!, request.Tenant, request.IncludeAllTenants,
                grant.UserId, AccountSecurityOperation.ReadAuthorizationGrant, cancellationToken))
            return Result.Failure<AuthorizationGrantAdministrationSummary>(AshlarFailureCodes.AuthorizationGrantNotFound, "Authorization grant was not found.");

        await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadAuthorizationGrant);
        return Result.Success(grant);
    }

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
}
