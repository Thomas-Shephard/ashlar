using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;

namespace Ashlar.Authorization;

/// <summary>
/// Provides authorization evaluator behavior.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <param name="options">The options value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class AuthorizationEvaluator(
    IAuthorizationGrantRepository repository,
    AuthorizationGrantOptions? options = null,
    TimeProvider? timeProvider = null) : IAuthorizationEvaluator
{
    private readonly IAuthorizationGrantRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly AuthorizationGrantOptions _options = ValidateOptions(options ?? new AuthorizationGrantOptions());
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Performs the evaluate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public async Task<AuthorizationEvaluationResult> EvaluateAsync(AuthorizationEvaluationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        AuthorizationGrantService.ValidateUserId(request.UserId);
        AuthorizationGrantService.ValidateGrantShape(request.Role, request.Permission);
        string? role;
        string? permission;
        string? scopeType;
        string? scopeId;
        try
        {
            role = AuthorizationGrantService.NormalizeOptional(request.Role, nameof(request.Role), _options.MaxRoleLength);
            permission = AuthorizationGrantService.NormalizeOptional(request.Permission, nameof(request.Permission), _options.MaxPermissionLength);
            scopeType = AuthorizationGrantService.NormalizeOptional(request.ScopeType, nameof(request.ScopeType), _options.MaxScopeTypeLength);
            scopeId = AuthorizationGrantService.NormalizeOptional(request.ScopeId, nameof(request.ScopeId), _options.MaxScopeIdLength);
            AuthorizationGrantService.ValidateScopeShape(scopeType, scopeId);
        }
        catch (ArgumentException)
        {
            return AuthorizationEvaluationResult.Failed;
        }

        var grants = await _repository.ListGrantsAsync(
            new ListAuthorizationGrantsRequest(request.UserId, request.TenantId, scopeType, scopeId, ActiveOnly: true, ExactMatch: true),
            cancellationToken);
        var now = _timeProvider.GetUtcNow();
        var match = grants.FirstOrDefault(grant =>
            grant.IsActive(now)
            && grant.TenantId == request.TenantId
            && string.Equals(grant.ScopeType, scopeType, StringComparison.Ordinal)
            && string.Equals(grant.ScopeId, scopeId, StringComparison.Ordinal)
            && ((role != null && string.Equals(grant.Role, role, StringComparison.Ordinal))
                || (permission != null && string.Equals(grant.Permission, permission, StringComparison.Ordinal))));

        return match == null ? AuthorizationEvaluationResult.Failed : new AuthorizationEvaluationResult(true, match);
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
