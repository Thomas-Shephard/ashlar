using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using System.Text.Json;

namespace Ashlar.Authorization;

public sealed class AuthorizationGrantService : IAuthorizationGrantService
{
    private readonly IAuthorizationGrantRepository _repository;
    private readonly AuthorizationGrantOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;

    public AuthorizationGrantService(
        IAuthorizationGrantRepository repository,
        AuthorizationGrantOptions? options = null,
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _options = options ?? new AuthorizationGrantOptions();
        if (!AuthorizationGrantOptions.Validate(_options))
        {
            throw new ArgumentException("Authorization grant options are invalid.", nameof(options));
        }

        _timeProvider = timeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(securityEventSink, _timeProvider);
    }

    public async Task<AuthorizationGrant> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateUserId(request.UserId);
        ValidateGrantShape(request.Role, request.Permission);
        var role = NormalizeOptional(request.Role, nameof(request.Role), _options.MaxRoleLength);
        var permission = NormalizeOptional(request.Permission, nameof(request.Permission), _options.MaxPermissionLength);
        var scopeType = NormalizeOptional(request.ScopeType, nameof(request.ScopeType), _options.MaxScopeTypeLength);
        var scopeId = NormalizeOptional(request.ScopeId, nameof(request.ScopeId), _options.MaxScopeIdLength);
        ValidateScopeShape(scopeType, scopeId);
        var metadata = string.IsNullOrWhiteSpace(request.Metadata) ? null : request.Metadata;
        ValidateMetadata(metadata, _options.MaxMetadataLength);
        ValidateMetadataJson(metadata);

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
            Properties = CreateAuditProperties(grant)
        }, cancellationToken);

        return grant;
    }

    public async Task<bool> RevokeGrantAsync(RevokeAuthorizationGrantRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.GrantId == Guid.Empty)
        {
            throw new ArgumentException("Grant id must not be empty.", nameof(request));
        }

        var grant = await _repository.GetGrantAsync(request.GrantId, cancellationToken);
        var revoked = await _repository.RevokeGrantAsync(request.GrantId, _timeProvider.GetUtcNow(), cancellationToken);
        if (revoked)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthorizationGrantRevoked,
                Outcome = SecurityEventOutcomes.Success,
                UserId = grant?.UserId,
                Properties = CreateAuditProperties(request.GrantId, grant)
            }, cancellationToken);
        }

        return revoked;
    }

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

    private static void ValidateMetadata(string? metadata, int maxLength)
    {
        if (metadata is { Length: > 0 } && metadata.Length > maxLength)
        {
            throw new ArgumentException("Metadata exceeds the configured maximum length.", nameof(metadata));
        }
    }

    private static void ValidateMetadataJson(string? metadata)
    {
        if (metadata == null)
        {
            return;
        }

        try
        {
            using var _ = JsonDocument.Parse(metadata);
        }
        catch (JsonException exception)
        {
            throw new ArgumentException("Metadata must be valid JSON.", nameof(metadata), exception);
        }
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
}
