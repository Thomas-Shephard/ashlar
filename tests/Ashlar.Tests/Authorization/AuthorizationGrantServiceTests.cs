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
    private AuditContext _audit;
    private RecordingTransactionProvider _transactions;

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        _repository = new FakeRepository();
        _userRepository = new FakeUserRepository();
        _transactions = new RecordingTransactionProvider();
        _service = CreateService();
        _audit = new AuditContext(ActorUserId: Guid.NewGuid(), IpAddress: "203.0.113.10", UserAgent: "unit-test", CorrelationId: "grant-test");
    }

    [Test]
    public async Task CreateGrantAsyncShouldNormalizeAndStorePermissionGrant()
    {
        var userId = AddGlobalUser();

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: " Posts.Edit ", Metadata: "{}"));

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
        var service = CreateService(auditSink);
        var userId = AddGlobalUser();

        await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "posts.edit"));

        var createdEvent = auditSink.Events.Single(securityEvent => securityEvent.EventType == AshlarSecurityEventTypes.AuthorizationGrantCreated);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(createdEvent.ActorUserId, Is.EqualTo(_audit.ActorUserId));
            Assert.That(createdEvent.IpAddress, Is.EqualTo(_audit.IpAddress));
            Assert.That(createdEvent.UserAgent, Is.EqualTo(_audit.UserAgent));
            Assert.That(createdEvent.CorrelationId, Is.EqualTo(_audit.CorrelationId));
            Assert.That(createdEvent.Properties?["grant_type"], Is.EqualTo("permission"));
            Assert.That(createdEvent.Properties?["grant_value"], Is.EqualTo("posts.edit"));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldCommitWhenTransactionProviderIsConfigured()
    {
        var transactionProvider = new RecordingTransactionProvider();
        var service = CreateService(transactionProvider: transactionProvider);
        var userId = AddGlobalUser();

        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "posts.read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(transactionProvider.Transaction.BeginCount, Is.EqualTo(1));
            Assert.That(transactionProvider.Transaction.CommitCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldRejectMissingAuditBeforeRepositoryCreation()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = CreateService(auditSink);
        var userId = AddGlobalUser();

        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, null!, Permission: "read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(_repository.Grants, Is.Empty);
            AssertSanitizedRejection(auditSink.Events.Single(), AshlarSecurityEventTypes.AuthorizationGrantCreated);
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldNormalizeBlankMetadataToNull()
    {
        var userId = AddGlobalUser();

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "read", Metadata: " "));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.Metadata, Is.Null);
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldRejectInvalidJsonMetadata()
    {
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), _audit, Permission: "read", Metadata: "{invalid"));
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

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Role: " ", Permission: "read"));

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

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, tenantId, " Project ", " ABC ", Role: " Reviewer "));

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

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "read"));

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

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, requestedTenantId, Permission: "read"));

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

        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, requestedTenantId, Permission: "read"));

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
        var service = CreateService(auditSink);
        var userId = Guid.NewGuid();
        var userTenantId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        _userRepository.Add(userId, userTenantId);

        await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, requestedTenantId, Permission: "read"));

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
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantService(_repository, null!,
            new SecurityEventFanOutSink(new RecordingSecurityEventSink(), transactionProvider: _transactions), _transactions));
    }

    [Test]
    public async Task CreateGrantAsyncShouldRejectMissingUserBeforeRepositoryCreation()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = CreateService(auditSink);
        var userId = Guid.NewGuid();

        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "read"));

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

        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.Empty, _audit, Permission: "x")));
        var missingGrant = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit));
        var roleAndPermission = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Role: "r", Permission: "p"));
        var missingScopeId = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, ScopeType: "project", Permission: "p"));
        var missingScopeType = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, ScopeId: "1", Permission: "p"));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingGrant.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidGrantShape));
            Assert.That(roleAndPermission.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidGrantShape));
            Assert.That(missingScopeId.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidScopeShape));
            Assert.That(missingScopeType.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidScopeShape));
        }
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.CreateGrantAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeGrantAsync(null!));
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(Guid.Empty, _audit)));
    }

    [Test]
    public async Task CreateGrantAsyncShouldRejectOversizedValues()
    {
        var service = CreateService(options: new AuthorizationGrantOptions
        {
            MaxRoleLength = 1,
            MaxPermissionLength = 1,
            MaxScopeTypeLength = 1,
            MaxScopeIdLength = 1,
            MaxMetadataLength = 1
        });
        var userId = Guid.NewGuid();

        var role = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Role: "xx"));
        var permission = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "xx"));
        var scopeType = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, ScopeType: "xx", ScopeId: "1", Permission: "x"));
        var scopeId = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, ScopeType: "x", ScopeId: "12", Permission: "x"));
        var metadata = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "x", Metadata: "{}"));

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
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, tenantId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, tenantId));

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
    public async Task RevokeGrantAsyncShouldCommitWhenTransactionProviderIsConfigured()
    {
        var userId = AddGlobalUser();
        var create = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "posts.read"));
        var transactionProvider = new RecordingTransactionProvider();
        var service = CreateService(transactionProvider: transactionProvider);

        var revoked = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(create.Value!.Id, _audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.Revoked));
            Assert.That(transactionProvider.Transaction.BeginCount, Is.EqualTo(1));
            Assert.That(transactionProvider.Transaction.CommitCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldRejectMissingAuditBeforeStorageLookup()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = CreateService(auditSink);
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, tenantId);
        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, tenantId, Permission: "read"));
        var grant = result.Value!;
        _repository.GetCalls = 0;
        auditSink.Events.Clear();

        var revoked = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, null!, tenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked.Status, Is.EqualTo(AuthorizationGrantRevocationStatus.ValidationFailed));
            Assert.That(revoked.GrantId, Is.EqualTo(grant.Id));
            Assert.That(revoked.TenantId, Is.EqualTo(tenantId));
            Assert.That(revoked.UserId, Is.Null);
            Assert.That(grant.RevokedAt, Is.Null);
            Assert.That(_repository.GetCalls, Is.Zero);
            Assert.That(_repository.RevokeCalls, Is.Zero);
            AssertSanitizedRejection(auditSink.Events.Single(), AshlarSecurityEventTypes.AuthorizationGrantRevoked);
        }
    }

    private static void AssertSanitizedRejection(AshlarSecurityEvent securityEvent, string eventType)
    {
        Assert.That(securityEvent.EventType == eventType
            && securityEvent.Outcome == SecurityEventOutcomes.Failure
            && securityEvent.UserId is null
            && securityEvent.TenantId is null
            && (securityEvent.Properties is null || securityEvent.Properties.Count == 0), Is.True);
    }

    [Test]
    public async Task RevokeGrantAsyncShouldRevokeGlobalGrantWhenRequestedTenantIsNull()
    {
        var userId = AddGlobalUser();
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, TenantId: null));

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
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, tenantId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, TenantId: null));

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
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, Guid.NewGuid()));

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
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, tenantId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, Guid.NewGuid()));

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
        var result = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, tenantId, Permission: "read"));
        var grant = result.Value!;

        var first = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, tenantId));
        var second = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, tenantId));

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
        var service = CreateService(auditSink);
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, tenantId);
        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, tenantId, Permission: "read"));
        var grant = result.Value!;
        await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, tenantId));

        var revokedAgain = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, tenantId));

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
        var service = CreateService(auditSink);
        var userId = AddGlobalUser();
        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Permission: "read"));
        var grant = result.Value!;

        await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit));

        var revokedEvent = auditSink.Events.Single(securityEvent => securityEvent.EventType == AshlarSecurityEventTypes.AuthorizationGrantRevoked);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokedEvent.ActorUserId, Is.EqualTo(_audit.ActorUserId));
            Assert.That(revokedEvent.IpAddress, Is.EqualTo(_audit.IpAddress));
            Assert.That(revokedEvent.UserAgent, Is.EqualTo(_audit.UserAgent));
            Assert.That(revokedEvent.CorrelationId, Is.EqualTo(_audit.CorrelationId));
            Assert.That(revokedEvent.UserId, Is.EqualTo(grant.UserId));
            Assert.That(revokedEvent.Properties?["grant_type"], Is.EqualTo("permission"));
            Assert.That(revokedEvent.Properties?["grant_value"], Is.EqualTo("read"));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldIncludeGrantActionInAuditEvent()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = CreateService(auditSink);
        var userId = AddGlobalUser();

        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, Role: "Reviewer"));
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
        var service = CreateService(auditSink, repository: new RevokesMissingGrantRepository());
        var grantId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var revoked = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grantId, _audit, tenantId));

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
        var service = CreateService(auditSink);
        var grantTenantId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, grantTenantId);
        var result = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, _audit, grantTenantId, Permission: "read"));
        var grant = result.Value!;

        var revoked = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit, requestedTenantId));

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
        var service = CreateService(auditSink);
        var grant = new AuthorizationGrant
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            CreatedAt = _timeProvider.GetUtcNow()
        };
        _repository.Grants.Add(grant);

        await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id, _audit));

        var revokedEvent = auditSink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokedEvent.Properties?["grant_id"], Is.EqualTo(grant.Id.ToString("D")));
            Assert.That(revokedEvent.Properties?.ContainsKey("grant_type"), Is.False);
            Assert.That(revokedEvent.Properties?.ContainsKey("grant_value"), Is.False);
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorsShouldRejectInvalidDependenciesAndOptions()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantService(null!, _userRepository,
            new SecurityEventFanOutSink(new RecordingSecurityEventSink(), transactionProvider: _transactions), _transactions));
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantService(_repository, null!,
            new SecurityEventFanOutSink(new RecordingSecurityEventSink(), transactionProvider: _transactions), _transactions));
        Assert.Throws<ArgumentNullException>(() => AuthorizationGrantOptions.Validate(null!));
        Assert.Throws<ArgumentException>(() => _ = CreateService(options: new AuthorizationGrantOptions { MaxRoleLength = 0 }));
        Assert.Throws<ArgumentException>(() => _ = new AuthorizationEvaluator(_repository, new AuthorizationGrantOptions { MaxMetadataLength = 0 }));
    }

    [Test]
    public void ConstructorRequiresDurableTransactionsForPersistentAudit()
    {
        var persistent = Moq.Mock.Of<IPersistentSecurityEventSink>();
        var auditlessFanOut = new SecurityEventFanOutSink();
        var transactionProvider = Moq.Mock.Of<IAshlarDurableTransactionProvider>();
        var boundFanOut = new SecurityEventFanOutSink(persistent, transactionProvider: transactionProvider);
        var durableHandlerFanOut = new SecurityEventFanOutSink(transactionProvider: transactionProvider,
            durableHandlers: [Moq.Mock.Of<IDurableSecurityEventFanOutHandler>()]);

        Assert.Throws<ArgumentNullException>(() => new AuthorizationGrantService(_repository, _userRepository, null!, transactionProvider));
        Assert.Throws<ArgumentNullException>(() => new AuthorizationGrantService(_repository, _userRepository, boundFanOut, null!));
        Assert.Throws<InvalidOperationException>(() => new SecurityEventFanOutSink(persistent));
        Assert.Throws<ArgumentException>(() => new AuthorizationGrantService(_repository, _userRepository, auditlessFanOut, transactionProvider));
        Assert.Throws<ArgumentException>(() => new AuthorizationGrantService(_repository, _userRepository, boundFanOut,
            Moq.Mock.Of<IAshlarDurableTransactionProvider>()));
        Assert.DoesNotThrow(() => new AuthorizationGrantService(_repository, _userRepository, boundFanOut, transactionProvider));
        Assert.DoesNotThrow(() => new AuthorizationGrantService(_repository, _userRepository, durableHandlerFanOut, transactionProvider));
    }

    private Guid AddGlobalUser()
    {
        var userId = Guid.NewGuid();
        _userRepository.Add(userId, null);
        return userId;
    }

    private AuthorizationGrantService CreateService(
        RecordingSecurityEventSink? audit = null,
        RecordingTransactionProvider? transactionProvider = null,
        IAuthorizationGrantRepository? repository = null,
        AuthorizationGrantOptions? options = null)
    {
        transactionProvider ??= _transactions;
        var fanOut = new SecurityEventFanOutSink(audit ?? new RecordingSecurityEventSink(), transactionProvider: transactionProvider);
        return new AuthorizationGrantService(repository ?? _repository, _userRepository, fanOut, transactionProvider,
            options, _timeProvider);
    }

    private sealed class FakeRepository : IAuthorizationGrantRepository
    {
        public List<AuthorizationGrant> Grants { get; } = [];
        public ListAuthorizationGrantsRequest? LastListRequest { get; private set; }
        public Guid? LastRevokedTenantId { get; private set; }
        public int GetCalls { get; set; }
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
            GetCalls++;
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

    private sealed class RecordingSecurityEventSink : IPersistentSecurityEventSink
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
            _users[userId] = new User { Id = userId, DisplayEmail = $"{userId:N}@example.com", TenantId = tenantId };
        }

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            var normalizedEmail = IdentityNormalization.NormalizeEmail(email);
            return Task.FromResult<IUser?>(_users.Values.FirstOrDefault(user =>
                IdentityNormalization.NormalizeEmail(user.DisplayEmail) == normalizedEmail
                && user.TenantId == tenantId));
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
            _users[user.Id] = new User { Id = user.Id, DisplayEmail = user.DisplayEmail, Name = user.Name, AccountState = user.AccountState, TenantId = user is ITenantUser tenantUser ? tenantUser.TenantId : null };
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
