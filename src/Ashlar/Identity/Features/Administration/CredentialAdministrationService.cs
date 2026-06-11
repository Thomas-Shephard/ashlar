namespace Ashlar.Identity.Features.Administration;

/// <summary>
/// Implements read-only administrator credential search and detail operations.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <remarks>
/// These operations are intended for administrative diagnostics and operations tooling and do not authorize the caller.
/// Host applications must protect usage of this service with appropriate admin authorization and step-up policy.
/// </remarks>
public sealed class CredentialAdministrationService(
    ICredentialAdministrationRepository repository,
    TimeProvider? timeProvider = null)
    : ICredentialAdministrationService
{
    internal const int MaximumLimit = 100;

    private readonly ICredentialAdministrationRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

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

        var limit = Math.Min(request.Limit, MaximumLimit);
        var repositoryRequest = request with { Limit = limit + 1 };
        var credentials = await _repository.SearchCredentialsAsync(repositoryRequest, _timeProvider.GetUtcNow(), cancellationToken);
        var hasMore = credentials.Count > limit;
        var page = credentials.Take(limit).ToList().AsReadOnly();

        return Result.Success(new CredentialSearchResult(page, limit, request.Offset, hasMore));
    }

    /// <inheritdoc />
    public async Task<Result<CredentialAdministrationDetail>> GetCredentialAsync(CredentialAdministrationDetailRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!TryValidateDetailRequest(request, out var validationFailure))
        {
            return validationFailure;
        }

        var credential = await _repository.GetCredentialAsync(request, _timeProvider.GetUtcNow(), cancellationToken);
        return credential == null || (!request.IncludeAllTenants && !AdministrationScopeValidation.IncludesTenant(request.Tenant!, credential.TenantId))
            ? Result.Failure<CredentialAdministrationDetail>(AshlarFailureCodes.CredentialNotFound, "Credential was not found.")
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

    private static bool TryValidateDetailRequest(CredentialAdministrationDetailRequest request, out Result<CredentialAdministrationDetail> failure)
    {
        try
        {
            CredentialAdministrationDetailRequest.ThrowIfInvalid(request);
            failure = null!;
            return true;
        }
        catch (ArgumentException exception)
        {
            failure = Result.Failure<CredentialAdministrationDetail>(AshlarFailureCodes.ValidationError, exception.Message);
            return false;
        }
    }
}
