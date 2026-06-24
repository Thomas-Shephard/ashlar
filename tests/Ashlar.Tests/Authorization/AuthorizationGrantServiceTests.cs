using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Authorization;

internal sealed class AuthorizationGrantServiceTests
{
    private FakeTimeProvider _timeProvider;
    private FakeRepository _repository;
    private FakeUserRepository _userRepository;
    private AuthorizationGrantService _service;

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        _repository = new FakeRepository();
        _userRepository = new FakeUserRepository();
        _service = new AuthorizationGrantService(_repository, _userRepository, timeProvider: _timeProvider);
    }

    [Test]
    public async Task CreateGrantAsyncShouldNormalizeAndStorePermissionGrant()
    {
        var userId = AddGlobalUser();

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: " Posts.Edit ", Metadata: "{}"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.EqualTo(userId));
            Assert.That(result.Value.Permission, Is.EqualTo("posts.edit"));
            Assert.That(result.Value.Role, Is.Null);
            Assert.That(result.Value.CreatedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(_repository.Grants, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldAuditPermissionGrantProperties()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(_repository, _userRepository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var userId = AddGlobalUser();

        await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "posts.edit"));

        var createdEvent = auditSink.Events.Single(securityEvent => securityEvent.EventType == AshlarSecurityEventTypes.AuthorizationGrantCreated);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(createdEvent.Properties?["grant_type"], Is.EqualTo("permission"));
            Assert.That(createdEvent.Properties?["grant_value"], Is.EqualTo("posts.edit"));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldNormalizeBlankMetadataToNull()
    {
        var userId = AddGlobalUser();

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "read", Metadata: " "));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.Metadata, Is.Null);
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldRejectInvalidJsonMetadata()
    {
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), Permission: "read", Metadata: "{invalid"));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidMetadataJson));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldTreatWhitespaceOptionalRoleAsMissing()
    {
        var userId = AddGlobalUser();

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Role: " ", Permission: "read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.Role, Is.Null);
            Assert.That(result.Value.Permission, Is.EqualTo("read"));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldStoreScopedRoleGrant()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        _userRepository.Add(userId, tenantId);

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, tenantId, " Project ", " ABC ", Role: " Reviewer "));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.TenantId, Is.EqualTo(tenantId));
            Assert.That(result.Value.ScopeType, Is.EqualTo("project"));
            Assert.That(result.Value.ScopeId, Is.EqualTo("abc"));
            Assert.That(result.Value.Role, Is.EqualTo("reviewer"));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldSucceedForGlobalUserWithNullTenant()
    {
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, null);

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.TenantId, Is.Null);
            Assert.That(_repository.Grants, Has.Count.EqualTo(1));
        }
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task CreateGrantAsyncShouldRejectTenantMismatchesBeforeRepositoryCreation(bool requestedTenantIsNull)
    {
        var userId = Guid.NewGuid();
        var userTenantId = Guid.NewGuid();
        var requestedTenantId = requestedTenantIsNull ? (Guid?)null : Guid.NewGuid();
        _userRepository.Add(userId, userTenantId);

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, requestedTenantId, Permission: "read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_repository.Grants, Is.Empty);
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldRejectTenantGrantForGlobalUserBeforeRepositoryCreation()
    {
        var userId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        _userRepository.Add(userId, null);

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, requestedTenantId, Permission: "read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(_repository.Grants, Is.Empty);
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldAuditTenantMismatchWithoutLeakingOtherTenantDetails()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(_repository, _userRepository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var userId = Guid.NewGuid();
        var userTenantId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        _userRepository.Add(userId, userTenantId);

        await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, requestedTenantId, Permission: "read"));

        var securityEvent = auditSink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.UserId, Is.EqualTo(userId));
            Assert.That(securityEvent.TenantId, Is.EqualTo(requestedTenantId));
            Assert.That(securityEvent.FailureReason, Is.EqualTo(AshlarFailureCodes.TenantMismatchValue));
            Assert.That(securityEvent.Properties, Is.Null);
        }
    }

    [Test]
    public void ConstructorShouldRequireUserRepositoryForTenantValidation()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantService(_repository, null!, timeProvider: _timeProvider));
    }

    [Test]
    public async Task CreateGrantAsyncShouldRejectMissingUserBeforeRepositoryCreation()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(_repository, _userRepository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var userId = Guid.NewGuid();

        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(_repository.Grants, Is.Empty);
            Assert.That(auditSink.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.UserNotFoundValue));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public async Task CreateGrantAsyncShouldRejectInvalidShapes()
    {
        var userId = Guid.NewGuid();

        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.Empty, Permission: "x")));
        var missingGrant = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId));
        var roleAndPermission = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Role: "r", Permission: "p"));
        var missingScopeId = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, ScopeType: "project", Permission: "p"));
        var missingScopeType = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, ScopeId: "1", Permission: "p"));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingGrant.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidGrantShape));
            Assert.That(roleAndPermission.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidGrantShape));
            Assert.That(missingScopeId.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidScopeShape));
            Assert.That(missingScopeType.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidScopeShape));
        }
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.CreateGrantAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.ListGrantsAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeGrantAsync(null!));
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(Guid.Empty)));
    }

    [Test]
    public async Task CreateGrantAsyncShouldRejectOversizedValues()
    {
        var service = new AuthorizationGrantService(_repository, _userRepository, new AuthorizationGrantOptions
        {
            MaxRoleLength = 1,
            MaxPermissionLength = 1,
            MaxScopeTypeLength = 1,
            MaxScopeIdLength = 1,
            MaxMetadataLength = 1
        }, timeProvider: null, securityEventSink: null);
        var userId = Guid.NewGuid();

        var role = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Role: "xx"));
        var permission = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "xx"));
        var scopeType = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, ScopeType: "xx", ScopeId: "1", Permission: "x"));
        var scopeId = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, ScopeType: "x", ScopeId: "12", Permission: "x"));
        var metadata = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "x", Metadata: "{}"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(role.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(permission.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(scopeType.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(scopeId.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(metadata.FailureCode, Is.EqualTo(AshlarFailureCodes.MetadataTooLong));
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldRevokeWhenGrantIdAndTenantMatch()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, tenantId);
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, tenantId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.Revoked));
            Assert.That(revoked.GrantId, Is.EqualTo(grant.Id));
            Assert.That(revoked.TenantId, Is.EqualTo(tenantId));
            Assert.That(revoked.UserId, Is.EqualTo(userId));
            Assert.That(grant.RevokedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(_repository.LastRevokedTenantId, Is.EqualTo(tenantId));
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldRevokeGlobalGrantWhenRequestedTenantIsNull()
    {
        var userId = AddGlobalUser();
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, TenantId: null));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.Revoked));
            Assert.That(revoked.GrantId, Is.EqualTo(grant.Id));
            Assert.That(revoked.TenantId, Is.Null);
            Assert.That(revoked.UserId, Is.EqualTo(userId));
            Assert.That(grant.RevokedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(_repository.LastRevokedTenantId, Is.Null);
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldNotRevokeTenantGrantWhenRequestedTenantIsNull()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, tenantId);
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, tenantId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, TenantId: null));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.NotFound));
            Assert.That(revoked.GrantId, Is.EqualTo(grant.Id));
            Assert.That(revoked.TenantId, Is.Null);
            Assert.That(revoked.UserId, Is.Null);
            Assert.That(grant.RevokedAt, Is.Null);
            Assert.That(_repository.RevokeCalls, Is.Zero);
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldNotRevokeGlobalGrantWhenRequestedTenantIsNonNull()
    {
        var userId = AddGlobalUser();
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.NotFound));
            Assert.That(revoked.GrantId, Is.EqualTo(grant.Id));
            Assert.That(revoked.TenantId, Is.Not.Null);
            Assert.That(revoked.UserId, Is.Null);
            Assert.That(grant.RevokedAt, Is.Null);
            Assert.That(_repository.RevokeCalls, Is.Zero);
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldNotRevokeWhenRequestedTenantDiffers()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, tenantId);
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, tenantId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.NotFound));
            Assert.That(revoked.GrantId, Is.EqualTo(grant.Id));
            Assert.That(revoked.TenantId, Is.Not.EqualTo(tenantId));
            Assert.That(revoked.UserId, Is.Null);
            Assert.That(grant.RevokedAt, Is.Null);
            Assert.That(_repository.RevokeCalls, Is.Zero);
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldBeIdempotentWithinTenantScope()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, tenantId);
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, tenantId, Permission: "read"));
        var grant = result.Value!;

        var first = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, tenantId));
        var second = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.Revoked));
            Assert.That(second.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.NotRevoked));
            Assert.That(second.UserId, Is.EqualTo(userId));
            Assert.That(grant.RevokedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldAuditVerifiedGrantDetailsWhenRepositoryDoesNotRevoke()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(_repository, _userRepository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, tenantId);
        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, tenantId, Permission: "read"));
        var grant = result.Value!;
        await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, tenantId));

        var revokedAgain = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, tenantId));

        var failedRevokedEvent = auditSink.Events
            .Where(securityEvent => securityEvent.EventType == AshlarSecurityEventTypes.AuthorizationGrantRevoked)
            .Single(securityEvent => securityEvent.Outcome == SecurityEventOutcomes.Failure);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokedAgain.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.NotRevoked));
            Assert.That(revokedAgain.UserId, Is.EqualTo(userId));
            Assert.That(failedRevokedEvent.UserId, Is.EqualTo(grant.UserId));
            Assert.That(failedRevokedEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(failedRevokedEvent.Properties?["grant_id"], Is.EqualTo(grant.Id.ToString("D")));
            Assert.That(failedRevokedEvent.Properties?["grant_type"], Is.EqualTo("permission"));
            Assert.That(failedRevokedEvent.Properties?["grant_value"], Is.EqualTo("read"));
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldIncludeUserIdInAuditEvent()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(_repository, _userRepository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var userId = AddGlobalUser();
        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "read"));
        var grant = result.Value!;

        await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id));

        var revokedEvent = auditSink.Events.Single(securityEvent => securityEvent.EventType == AshlarSecurityEventTypes.AuthorizationGrantRevoked);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokedEvent.UserId, Is.EqualTo(grant.UserId));
            Assert.That(revokedEvent.Properties?["grant_type"], Is.EqualTo("permission"));
            Assert.That(revokedEvent.Properties?["grant_value"], Is.EqualTo("read"));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldIncludeGrantActionInAuditEvent()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(_repository, _userRepository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var userId = AddGlobalUser();

        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Role: "Reviewer"));
        var grant = result.Value!;

        var createdEvent = auditSink.Events.Single(securityEvent => securityEvent.EventType == AshlarSecurityEventTypes.AuthorizationGrantCreated);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(createdEvent.Properties?["grant_id"], Is.EqualTo(grant.Id.ToString("D")));
            Assert.That(createdEvent.Properties?["grant_type"], Is.EqualTo("role"));
            Assert.That(createdEvent.Properties?["grant_value"], Is.EqualTo("reviewer"));
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldReturnNotFoundAndAuditWhenGrantContextIsUnavailable()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(new RevokesMissingGrantRepository(), _userRepository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var grantId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var revoked = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grantId, tenantId));

        var revokedEvent = auditSink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.NotFound));
            Assert.That(revoked.GrantId, Is.EqualTo(grantId));
            Assert.That(revoked.TenantId, Is.EqualTo(tenantId));
            Assert.That(revoked.UserId, Is.Null);
            Assert.That(revokedEvent.UserId, Is.Null);
            Assert.That(revokedEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(revokedEvent.Properties?["grant_id"], Is.EqualTo(grantId.ToString("D")));
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldAuditOutOfScopeRevocationWithoutGrantDetails()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(_repository, _userRepository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var grantTenantId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, grantTenantId);
        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, grantTenantId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, requestedTenantId));

        var revokedEvent = auditSink.Events.Single(securityEvent => securityEvent.EventType == AshlarSecurityEventTypes.AuthorizationGrantRevoked);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.NotFound));
            Assert.That(revoked.GrantId, Is.EqualTo(grant.Id));
            Assert.That(revoked.TenantId, Is.EqualTo(requestedTenantId));
            Assert.That(revoked.UserId, Is.Null);
            Assert.That(revokedEvent.UserId, Is.Null);
            Assert.That(revokedEvent.TenantId, Is.EqualTo(requestedTenantId));
            Assert.That(revokedEvent.FailureReason, Is.EqualTo("grant_not_found"));
            Assert.That(revokedEvent.Properties?["grant_id"], Is.EqualTo(grant.Id.ToString("D")));
            Assert.That(revokedEvent.Properties?.ContainsKey("grant_type"), Is.False);
            Assert.That(revokedEvent.Properties?.ContainsKey("grant_value"), Is.False);
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldAuditGrantIdWhenGrantHasNoRoleOrPermission()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(_repository, _userRepository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var grant = new AuthorizationGrant
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            CreatedAt = _timeProvider.GetUtcNow()
        };
        _repository.Grants.Add(grant);

        await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id));

        var revokedEvent = auditSink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokedEvent.Properties?["grant_id"], Is.EqualTo(grant.Id.ToString("D")));
            Assert.That(revokedEvent.Properties?.ContainsKey("grant_type"), Is.False);
            Assert.That(revokedEvent.Properties?.ContainsKey("grant_value"), Is.False);
        }
    }

    [Test]
    public async Task ListGrantsAsyncShouldValidateAndDelegate()
    {
        var userId = Guid.NewGuid();

        await _service.ListGrantsAsync(new ListAuthorizationGrantsRequest(userId, ScopeType: " Project ", ScopeId: " ABC "));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(_repository.LastListRequest?.UserId, Is.EqualTo(userId));
            Assert.That(_repository.LastListRequest?.ScopeType, Is.EqualTo("project"));
            Assert.That(_repository.LastListRequest?.ScopeId, Is.EqualTo("abc"));
        }
    }

    [Test]
    public async Task ListGrantsAsyncShouldReturnOnlyGlobalGrantsWhenTenantIsNull()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var global = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, Permission = "global", CreatedAt = _timeProvider.GetUtcNow() };
        var tenant = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, TenantId = tenantId, Permission = "tenant", CreatedAt = _timeProvider.GetUtcNow() };
        _repository.Grants.Add(global);
        _repository.Grants.Add(tenant);

        var grants = await _service.ListGrantsAsync(new ListAuthorizationGrantsRequest(userId));

        Assert.That(grants.Select(grant => grant.Id), Is.EquivalentTo(new[] { global.Id }));
    }

    [Test]
    public async Task ListGrantsAsyncShouldReturnOnlyRequestedTenantGrants()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var matching = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, TenantId = tenantId, Permission = "tenant", CreatedAt = _timeProvider.GetUtcNow() };
        var global = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, Permission = "global", CreatedAt = _timeProvider.GetUtcNow() };
        var otherTenant = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, TenantId = otherTenantId, Permission = "other", CreatedAt = _timeProvider.GetUtcNow() };
        _repository.Grants.AddRange([matching, global, otherTenant]);

        var grants = await _service.ListGrantsAsync(new ListAuthorizationGrantsRequest(userId, tenantId));

        Assert.That(grants.Select(grant => grant.Id), Is.EquivalentTo(new[] { matching.Id }));
    }

    [Test]
    public async Task ListGrantsAsyncShouldAllowBroadScopeWithoutBroadeningTenantBoundary()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var broadTenantGrant = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, TenantId = tenantId, Permission = "tenant", CreatedAt = _timeProvider.GetUtcNow() };
        var scopedTenantGrant = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, TenantId = tenantId, ScopeType = "project", ScopeId = "alpha", Permission = "scoped", CreatedAt = _timeProvider.GetUtcNow() };
        var broadOtherTenantGrant = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, TenantId = otherTenantId, Permission = "other", CreatedAt = _timeProvider.GetUtcNow() };
        var broadGlobalGrant = new AuthorizationGrant { Id = Guid.NewGuid(), UserId = userId, Permission = "global", CreatedAt = _timeProvider.GetUtcNow() };
        _repository.Grants.AddRange([broadTenantGrant, scopedTenantGrant, broadOtherTenantGrant, broadGlobalGrant]);

        var grants = await _service.ListGrantsAsync(new ListAuthorizationGrantsRequest(userId, tenantId, "project", "alpha"));

        Assert.That(grants.Select(grant => grant.Id), Is.EquivalentTo(new[] { broadTenantGrant.Id, scopedTenantGrant.Id }));
    }

    [Test]
    public async Task ListGrantsAsyncShouldReturnEmptyForInvalidSearchValues()
    {
        var userId = Guid.NewGuid();
        var service = new AuthorizationGrantService(_repository, _userRepository, new AuthorizationGrantOptions { MaxScopeTypeLength = 1 });

        var missingScopeId = await _service.ListGrantsAsync(new ListAuthorizationGrantsRequest(userId, ScopeType: "project"));
        var oversizedScope = await service.ListGrantsAsync(new ListAuthorizationGrantsRequest(userId, ScopeType: "project", ScopeId: "1"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingScopeId, Is.Empty);
            Assert.That(oversizedScope, Is.Empty);
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorsShouldRejectInvalidDependenciesAndOptions()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantService(null!, _userRepository));
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantService(_repository, null!));
        Assert.Throws<ArgumentNullException>(() => AuthorizationGrantOptions.Validate(null!));
        Assert.Throws<ArgumentException>(() => _ = new AuthorizationGrantService(_repository, _userRepository, new AuthorizationGrantOptions { MaxRoleLength = 0 }));
        Assert.Throws<ArgumentException>(() => _ = new AuthorizationEvaluator(_repository, new AuthorizationGrantOptions { MaxMetadataLength = 0 }));
    }

    private Guid AddGlobalUser()
    {
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, null);
        return userId;
    }

    private sealed class FakeRepository : IAuthorizationGrantRepository
    {
        public List<AuthorizationGrant> Grants { get; } = [];
        public ListAuthorizationGrantsRequest? LastListRequest { get; private set; }
        public Guid? LastRevokedTenantId { get; private set; }
        public int RevokeCalls { get; private set; }

        public Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default)
        {
            Grants.Add(grant);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
        {
            LastListRequest = request;
            var results = Grants
                .Where(grant => grant.UserId == request.UserId)
                .Where(grant => grant.TenantId == request.TenantId)
                .Where(grant => MatchesScope(grant, request))
                .Where(grant => !request.ActiveOnly || grant.RevokedAt == null && (grant.ExpiresAt == null || grant.ExpiresAt > DateTimeOffset.UtcNow))
                .ToList();
            return Task.FromResult<IReadOnlyList<AuthorizationGrant>>(results);
        }

        public Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, Guid? tenantId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Grants.FirstOrDefault(grant => grant.Id == grantId && grant.TenantId == tenantId));
        }

        public Task<bool> RevokeGrantAsync(Guid grantId, Guid? tenantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
        {
            LastRevokedTenantId = tenantId;
            RevokeCalls++;
            var grant = Grants.FirstOrDefault(item => item.Id == grantId && item.TenantId == tenantId);
            if (grant?.RevokedAt != null || grant == null)
            {
                return Task.FromResult(false);
            }

            grant.RevokedAt = revokedAt;
            return Task.FromResult(true);
        }

        private static bool MatchesScope(AuthorizationGrant grant, ListAuthorizationGrantsRequest request)
        {
            if (request.ExactMatch)
            {
                return grant.ScopeType == request.ScopeType && grant.ScopeId == request.ScopeId;
            }

            if (request.ScopeType == null && request.ScopeId == null)
            {
                return true;
            }

            return grant.ScopeType == null && grant.ScopeId == null || grant.ScopeType == request.ScopeType && grant.ScopeId == request.ScopeId;
        }
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeUserRepository : IUserRepository
    {
        private readonly Dictionary<Guid, User> _users = [];

        public void Add(Guid userId, Guid? tenantId)
        {
            _users[userId] = new User { Id = userId, Email = $"{userId:N}@example.com", TenantId = tenantId };
        }

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(_users.Values.FirstOrDefault(user => user.Email == email && user.TenantId == tenantId));
        }

        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(_users.GetValueOrDefault(userId));
        }

        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(null);
        }

        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            _users[user.Id] = new User { Id = user.Id, Email = user.Email, Name = user.Name, AccountState = user.AccountState, TenantId = user is ITenantUser tenantUser ? tenantUser.TenantId : null };
            return Task.CompletedTask;
        }

        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            return CreateUserAsync(user, cancellationToken);
        }
    }

    private sealed class RevokesMissingGrantRepository : IAuthorizationGrantRepository
    {
        public Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, Guid? tenantId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<AuthorizationGrant?>(null);
        }

        public Task<bool> RevokeGrantAsync(Guid grantId, Guid? tenantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }
    }
}
