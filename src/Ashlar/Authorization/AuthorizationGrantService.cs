using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using System.Text.Json;

namespace Ashlar.Authorization;

/// <summary>
/// Creates, revokes, and lists authorization grants for users.
/// </summary>
public sealed class AuthorizationGrantService : IAuthorizationGrantService
{
    private readonly IAuthorizationGrantRepository _repository;
    private readonly AuthorizationGrantOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly IUserRepository _userRepository;

    /// <summary>Initializes the grant service with storage, validation, and audit dependencies.</summary>
    /// <param name="repository">Grant storage used for authorization assignments.</param>
    /// <param name="userRepository">User repository used to verify tenant ownership.</param>
    /// <param name="options">Validation limits for grant fields.</param>
    /// <param name="timeProvider">Clock used for timestamps and expiration checks.</param>
    /// <param name="securityEventSink">Optional sink that receives grant creation and revocation audit events.</param>
    public AuthorizationGrantService(
        IAuthorizationGrantRepository repository,
        IUserRepository userRepository,
        AuthorizationGrantOptions? options = null,
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _options = options ?? new AuthorizationGrantOptions();
        if (!AuthorizationGrantOptions.Validate(_options))
        {
            throw new ArgumentException("Authorization grant options are invalid.", nameof(options));
        }

        _timeProvider = timeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(securityEventSink, _timeProvider);
    }

    /// <summary>
    /// Creates a role or permission grant after validating user and tenant ownership.
    /// </summary>
    /// <param name="request">Grant details supplied by an authorized caller.</param>
    /// <param name="cancellationToken">A token that can cancel the create operation.</param>
    /// <returns>Created grant, or a failure when validation or tenant checks fail.</returns>
    public async Task<Result<AuthorizationGrant>> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.UserId == Guid.Empty)
        {
            throw new ArgumentException("User id must not be empty.", nameof(request));
        }

        if (string.IsNullOrWhiteSpace(request.Role) == string.IsNullOrWhiteSpace(request.Permission))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthorizationGrantCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                TenantId = request.TenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidGrantShape.Value
            }, cancellationToken);
            return Result.Failure<AuthorizationGrant>(AshlarFailureCodes.InvalidGrantShape);
        }

        string? role;
        string? permission;
        string? scopeType;
        string? scopeId;

        try
        {
            role = NormalizeOptional(request.Role, nameof(request.Role), _options.MaxRoleLength);
            permission = NormalizeOptional(request.Permission, nameof(request.Permission), _options.MaxPermissionLength);
            scopeType = NormalizeOptional(request.ScopeType, nameof(request.ScopeType), _options.MaxScopeTypeLength);
            scopeId = NormalizeOptional(request.ScopeId, nameof(request.ScopeId), _options.MaxScopeIdLength);
        }
        catch (ArgumentException)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthorizationGrantCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                TenantId = request.TenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.ValidationError.Value
            }, cancellationToken);
            return Result.Failure<AuthorizationGrant>(AshlarFailureCodes.ValidationError);
        }

        if (string.IsNullOrWhiteSpace(scopeType) != string.IsNullOrWhiteSpace(scopeId))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthorizationGrantCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                TenantId = request.TenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.InvalidScopeShape.Value
            }, cancellationToken);
            return Result.Failure<AuthorizationGrant>(AshlarFailureCodes.InvalidScopeShape);
        }

        var metadata = string.IsNullOrWhiteSpace(request.Metadata) ? null : request.Metadata;

        if (metadata is { Length: > 0 } && metadata.Length > _options.MaxMetadataLength)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthorizationGrantCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                TenantId = request.TenantId,
                Audit = request.Audit,
                FailureReason = AshlarFailureCodes.MetadataTooLong.Value
            }, cancellationToken);
            return Result.Failure<AuthorizationGrant>(AshlarFailureCodes.MetadataTooLong);
        }

        if (metadata != null)
        {
            try
            {
                using var _ = JsonDocument.Parse(metadata);
            }
            catch (JsonException)
            {
                await _securityEvents.RecordAsync(new SecurityEventDescriptor
                {
                    EventType = AshlarSecurityEventTypes.AuthorizationGrantCreated,
                    Outcome = SecurityEventOutcomes.Failure,
                    UserId = request.UserId,
                    TenantId = request.TenantId,
                    Audit = request.Audit,
                    FailureReason = AshlarFailureCodes.InvalidMetadataJson.Value
                }, cancellationToken);
                return Result.Failure<AuthorizationGrant>(AshlarFailureCodes.InvalidMetadataJson);
            }
        }

        var tenantValidation = await ValidateUserTenantAsync(request.UserId, request.TenantId, request.Audit, cancellationToken);
        if (!tenantValidation.Succeeded)
        {
            return Result.Failure<AuthorizationGrant>(tenantValidation.FailureDetails!);
        }

        var grant = new AuthorizationGrant
        {
            Id = Guid.NewGuid(),
            UserId = request.UserId,
            TenantId = request.TenantId,
            ScopeType = scopeType,
            ScopeId = scopeId,
            Role = role,
            Permission = permission,
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = request.ExpiresAt,
            Metadata = metadata
        };

        await _repository.CreateGrantAsync(grant, cancellationToken);
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthorizationGrantCreated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = grant.UserId,
            TenantId = grant.TenantId,
            Audit = request.Audit,
            Properties = CreateAuditProperties(grant)
        }, cancellationToken);

        return Result<AuthorizationGrant>.Success(grant);
    }

    private async Task<Result> ValidateUserTenantAsync(Guid userId, Guid? tenantId, AuditContext? audit, CancellationToken cancellationToken)
    {
        var user = await _userRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthorizationGrantCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenantId,
                Audit = audit,
                FailureReason = AshlarFailureCodes.UserNotFoundValue
            }, cancellationToken);

            return Result.Failure(AshlarFailureCodes.UserNotFound);
        }

        if (UserTenantOwnership.Matches(user, tenantId))
        {
            return Result.Success();
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthorizationGrantCreated,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenantId,
            Audit = audit,
            FailureReason = AshlarFailureCodes.TenantMismatchValue
        }, cancellationToken);

        return Result.Failure(AshlarFailureCodes.TenantMismatch, "Grant tenant must match the referenced user's tenant.");
    }

    /// <summary>
    /// Revokes an authorization grant in the requested tenant scope.
    /// </summary>
    /// <param name="request">Grant identifier, tenant scope, and audit context for the revocation.</param>
    /// <param name="cancellationToken">A token that can cancel the revoke operation.</param>
    /// <returns>Revocation result with the grant id, requested tenant boundary, and outcome.</returns>
    public async Task<RevokeAuthorizationGrantResult> RevokeGrantAsync(RevokeAuthorizationGrantRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.GrantId == Guid.Empty)
        {
            throw new ArgumentException("Grant id must not be empty.", nameof(request));
        }

        var grant = await _repository.GetGrantAsync(request.GrantId, request.TenantId, cancellationToken);
        if (grant == null)
        {
            await RecordRevokeFailureAsync(request, "grant_not_found", cancellationToken);
            return new RevokeAuthorizationGrantResult(AuthorizationGrantRevocationStatus.NotFound, request.GrantId, request.TenantId);
        }

        var revoked = await _repository.RevokeGrantAsync(request.GrantId, request.TenantId, _timeProvider.GetUtcNow(), cancellationToken);
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthorizationGrantRevoked,
            Outcome = revoked ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
            UserId = grant.UserId,
            TenantId = request.TenantId,
            Audit = request.Audit,
            FailureReason = revoked ? null : "grant_not_revoked",
            Properties = CreateAuditProperties(grant)
        }, cancellationToken);

        var status = revoked ? AuthorizationGrantRevocationStatus.Revoked : AuthorizationGrantRevocationStatus.NotRevoked;
        return new RevokeAuthorizationGrantResult(status, request.GrantId, request.TenantId, grant.UserId);
    }

    /// <summary>
    /// Lists grants for a user, optionally narrowed to a tenant and resource scope.
    /// </summary>
    /// <param name="request">User, tenant, and optional scope filters for the query.</param>
    /// <param name="cancellationToken">A token that can cancel the list operation.</param>
    /// <returns>Grants visible for the supplied filters.</returns>
    public Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateUserId(request.UserId);
        string? scopeType;
        string? scopeId;
        try
        {
            scopeType = NormalizeOptional(request.ScopeType, nameof(request.ScopeType), _options.MaxScopeTypeLength);
            scopeId = NormalizeOptional(request.ScopeId, nameof(request.ScopeId), _options.MaxScopeIdLength);
            ValidateScopeShape(scopeType, scopeId);
        }
        catch (ArgumentException)
        {
            return Task.FromResult<IReadOnlyList<AuthorizationGrant>>([]);
        }

        return _repository.ListGrantsAsync(request with { ScopeType = scopeType, ScopeId = scopeId }, cancellationToken);
    }

    internal static void ValidateUserId(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User id must not be empty.", nameof(userId));
        }
    }

    internal static void ValidateGrantShape(string? role, string? permission)
    {
        if (string.IsNullOrWhiteSpace(role) == string.IsNullOrWhiteSpace(permission))
        {
            throw new ArgumentException("Exactly one role or permission must be specified.");
        }
    }

    internal static void ValidateScopeShape(string? scopeType, string? scopeId)
    {
        if (string.IsNullOrWhiteSpace(scopeType) != string.IsNullOrWhiteSpace(scopeId))
        {
            throw new ArgumentException("Scope type and scope id must be specified together.");
        }
    }

    internal static string? NormalizeOptional(string? value, string parameterName, int maxLength)
    {
        if (value == null)
        {
            return null;
        }

        var normalized = value.Trim().ToLowerInvariant();
        if (normalized.Length == 0)
        {
            return null;
        }

        if (normalized.Length > maxLength)
        {
            throw new ArgumentException("Value exceeds the configured maximum length.", parameterName);
        }

        return normalized;
    }

    private static Dictionary<string, string> CreateAuditProperties(AuthorizationGrant grant)
    {
        return CreateAuditProperties(grant.Id, grant);
    }

    private static Dictionary<string, string> CreateAuditProperties(Guid grantId, AuthorizationGrant? grant)
    {
        var properties = new Dictionary<string, string> { ["grant_id"] = grantId.ToString("D") };
        if (grant?.Role != null)
        {
            properties["grant_type"] = "role";
            properties["grant_value"] = grant.Role;
        }
        else if (grant?.Permission != null)
        {
            properties["grant_type"] = "permission";
            properties["grant_value"] = grant.Permission;
        }

        return properties;
    }

    /// <summary>
    /// Records a revocation failure security event.
    /// </summary>
    private Task RecordRevokeFailureAsync(RevokeAuthorizationGrantRequest request, string failureReason, CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthorizationGrantRevoked,
            Outcome = SecurityEventOutcomes.Failure,
            TenantId = request.TenantId,
            Audit = request.Audit,
            FailureReason = failureReason,
            Properties = CreateAuditProperties(request.GrantId, null)
        }, cancellationToken);
    }
}
