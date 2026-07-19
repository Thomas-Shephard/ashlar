using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Administration;

/// <summary>
/// Implements read-only administrator credential search and single-item lookup operations.
/// </summary>
/// <param name="repository">Repository used for safe administrator credential lookup.</param>
/// <param name="sessions">Authoritative session repository.</param>
/// <param name="authorizer">Required host authorization policy.</param>
/// <param name="auditSink">Required durable audit sink.</param>
/// <param name="timeProvider">Clock used for credential availability projection.</param>
/// <remarks>
/// Every operation enforces actor-bound active-session proof, scope, host authorization, and durable audit requirements.
/// </remarks>
public sealed class CredentialAdministrationService(
    ICredentialAdministrationRepository repository,
    IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink,
    TimeProvider? timeProvider = null)
    : ICredentialAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly ICredentialAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly AdminReadBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider ?? TimeProvider.System);

    /// <inheritdoc />
    public async Task<Result<CredentialSearchResult>> SearchCredentialsAsync(SearchCredentialsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateSearchRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (request.Offset < 0)
        {
            return Result.Failure<CredentialSearchResult>(AshlarFailureCodes.ValidationError, "Offset cannot be negative.");
        }

        if (request.Limit < 1)
        {
            return Result.Failure<CredentialSearchResult>(AshlarFailureCodes.ValidationError, "Limit must be greater than zero.");
        }

        if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                request.UserId ?? Guid.Empty, AccountSecurityOperation.SearchCredentials, cancellationToken))
            return Result.Failure<CredentialSearchResult>(AshlarFailureCodes.ValidationError);

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Actor = null, Limit = limit + 1 };
        List<CredentialAdministrationSummary> credentials;
        try
        {
            credentials = (await _repository.SearchCredentialsAsync(repositoryRequest, _timeProvider.GetUtcNow(), cancellationToken)).ToList();
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchCredentials);
            throw;
        }
        if (credentials.Any(credential => !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants,
                credential.TenantId, request.UserId, credential.UserId)))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchCredentials);
            throw new InvalidOperationException("The credential administration provider returned a result outside the authorized scope.");
        }
        await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.SearchCredentials);
        var hasMore = credentials.Count > limit;
        var page = credentials.Take(limit).ToList().AsReadOnly();

        return Result.Success(new CredentialSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<CredentialAdministrationSummary>> GetCredentialAsync(CredentialAdministrationLookupRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateLookupRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                Guid.Empty, AccountSecurityOperation.ReadCredential, cancellationToken))
            return Result.Failure<CredentialAdministrationSummary>(AshlarFailureCodes.ValidationError);

        CredentialAdministrationSummary? credential;
        try
        {
            credential = await _repository.GetCredentialAsync(request with { Actor = null }, _timeProvider.GetUtcNow(), cancellationToken);
        }
        catch
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadCredential);
            throw;
        }
        if (credential is null || credential.CredentialId != request.CredentialId
            || !AdministrationScopeValidation.IncludesResult(request.Tenant, request.IncludeAllTenants, credential.TenantId))
        {
            await _boundary.RecordFailureAsync(request.Actor!, request.Tenant, request.IncludeAllTenants, AccountSecurityOperation.ReadCredential);
            credential = null;
        }
        else if (!await _boundary.AuthorizeAsync(request.Actor, request.Tenant, request.IncludeAllTenants,
                credential.UserId, AccountSecurityOperation.ReadCredential, cancellationToken))
            credential = null;
        else
            await _boundary.RecordSuccessAsync(request.Actor!, request.Tenant, request.IncludeAllTenants,
                AccountSecurityOperation.ReadCredential);
        return credential == null
            ? Result.Failure<CredentialAdministrationSummary>(AshlarFailureCodes.CredentialNotFound, "Credential was not found.")
            : Result.Success(credential);
    }

    private static bool TryValidateSearchRequest(SearchCredentialsRequest request, out Result<CredentialSearchResult> failure)
    {
        try
        {
            SearchCredentialsRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<CredentialSearchResult>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }

    private static bool TryValidateLookupRequest(CredentialAdministrationLookupRequest request, out Result<CredentialAdministrationSummary> failure)
    {
        try
        {
            CredentialAdministrationLookupRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<CredentialAdministrationSummary>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}
