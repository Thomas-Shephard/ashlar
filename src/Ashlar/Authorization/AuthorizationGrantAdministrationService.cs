using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;

namespace Ashlar.Authorization;

/// <summary>
/// Implements read-only administrator authorization grant search and detail operations.
/// </summary>
/// <param name="repository">Repository used for safe administrator grant lookup.</param>
/// <param name="options">Validation limits for grant fields.</param>
/// <param name="timeProvider">Clock used for status projection.</param>
/// <remarks>
/// These operations are intended for administrative diagnostics and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and fresh step-up policy.
/// </remarks>
public sealed class AuthorizationGrantAdministrationService(
    IAuthorizationGrantAdministrationRepository repository,
    AuthorizationGrantOptions? options = null,
    TimeProvider? timeProvider = null)
    : IAuthorizationGrantAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly IAuthorizationGrantAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly AuthorizationGrantOptions _options = ValidateOptions(options ?? new AuthorizationGrantOptions());
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

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

        SearchAuthorizationGrantsRequest repositoryRequest;
        try
        {
            repositoryRequest = Normalize(request) with { Limit = Math.Min(request.Limit, MaximumLimit) + 1 };
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
    public async Task<Result<AuthorizationGrantAdministrationDetail>> GetAuthorizationGrantAsync(AuthorizationGrantAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateDetailRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var grant = await _repository.GetAuthorizationGrantAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        return grant == null || (!request.IncludeAllTenants && !AdministrationScopeValidation.IncludesTenant(request.Tenant!, grant.TenantId))
            ? Result.Failure<AuthorizationGrantAdministrationDetail>(AshlarFailureCodes.AuthorizationGrantNotFound, "Authorization grant was not found.")
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

    private static bool TryValidateDetailRequest(AuthorizationGrantAdministrationDetailRequest request, out Result<AuthorizationGrantAdministrationDetail> failure)
    {
        try
        {
            AuthorizationGrantAdministrationDetailRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<AuthorizationGrantAdministrationDetail>(AshlarFailureCodes.ValidationError, exception.Message);
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
