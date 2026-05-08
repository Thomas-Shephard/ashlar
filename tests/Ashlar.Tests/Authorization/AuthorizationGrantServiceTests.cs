using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Authorization;

public sealed class AuthorizationGrantServiceTests
{
    private FakeTimeProvider _timeProvider;
    private FakeRepository _repository;
    private AuthorizationGrantService _service;

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        _repository = new FakeRepository();
        _service = new AuthorizationGrantService(_repository, timeProvider: _timeProvider);
    }

    [Test]
    public async Task CreateGrantAsyncShouldNormalizeAndStorePermissionGrant()
    {
        var userId = Guid.NewGuid();

        var grant = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: " Posts.Edit ", Metadata: "{}"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(grant.UserId, Is.EqualTo(userId));
            Assert.That(grant.Permission, Is.EqualTo("posts.edit"));
            Assert.That(grant.Role, Is.Null);
            Assert.That(grant.CreatedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
            Assert.That(_repository.Grants, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldNormalizeBlankMetadataToNull()
    {
        var grant = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), Permission: "read", Metadata: " "));

        Assert.That(grant.Metadata, Is.Null);
    }

    [Test]
    public void CreateGrantAsyncShouldRejectInvalidJsonMetadata()
    {
        Assert.ThrowsAsync<ArgumentException>(() =>
            _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), Permission: "read", Metadata: "{invalid")));
    }

    [Test]
    public async Task CreateGrantAsyncShouldTreatWhitespaceOptionalRoleAsMissing()
    {
        var grant = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), Role: " ", Permission: "read"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(grant.Role, Is.Null);
            Assert.That(grant.Permission, Is.EqualTo("read"));
        }
    }

    [Test]
    public async Task CreateGrantAsyncShouldStoreScopedRoleGrant()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();

        var grant = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, tenantId, " Project ", " ABC ", Role: " Reviewer "));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(grant.TenantId, Is.EqualTo(tenantId));
            Assert.That(grant.ScopeType, Is.EqualTo("project"));
            Assert.That(grant.ScopeId, Is.EqualTo("abc"));
            Assert.That(grant.Role, Is.EqualTo("reviewer"));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void CreateGrantAsyncShouldRejectInvalidShapes()
    {
        var userId = Guid.NewGuid();

        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.Empty, Permission: "x")));
        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId)));
        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Role: "r", Permission: "p")));
        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, ScopeType: "project", Permission: "p")));
        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, ScopeId: "1", Permission: "p")));
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.CreateGrantAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.ListGrantsAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => _service.RevokeGrantAsync(null!));
        Assert.ThrowsAsync<ArgumentException>(() => _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(Guid.Empty)));
    }

    [Test]
    public void CreateGrantAsyncShouldRejectOversizedValues()
    {
        var service = new AuthorizationGrantService(_repository, new AuthorizationGrantOptions
        {
            MaxRoleLength = 1,
            MaxPermissionLength = 1,
            MaxScopeTypeLength = 1,
            MaxScopeIdLength = 1,
            MaxMetadataLength = 1
        });
        var userId = Guid.NewGuid();

        Assert.ThrowsAsync<ArgumentException>(() => service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Role: "xx")));
        Assert.ThrowsAsync<ArgumentException>(() => service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "xx")));
        Assert.ThrowsAsync<ArgumentException>(() => service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, ScopeType: "xx", ScopeId: "1", Permission: "x")));
        Assert.ThrowsAsync<ArgumentException>(() => service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, ScopeType: "x", ScopeId: "12", Permission: "x")));
        Assert.ThrowsAsync<ArgumentException>(() => service.CreateGrantAsync(new CreateAuthorizationGrantRequest(userId, Permission: "x", Metadata: "{}")));
    }

    [Test]
    public async Task RevokeGrantAsyncShouldBeIdempotent()
    {
        var grant = await _service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), Permission: "read"));

        var first = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id));
        var second = await _service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grant.Id));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Is.True);
            Assert.That(second, Is.False);
            Assert.That(grant.RevokedAt, Is.EqualTo(_timeProvider.GetUtcNow()));
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldIncludeUserIdInAuditEvent()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(_repository, timeProvider: _timeProvider, securityEventSink: auditSink);
        var grant = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), Permission: "read"));

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
        var service = new AuthorizationGrantService(_repository, timeProvider: _timeProvider, securityEventSink: auditSink);

        var grant = await service.CreateGrantAsync(new CreateAuthorizationGrantRequest(Guid.NewGuid(), Role: "Reviewer"));

        var createdEvent = auditSink.Events.Single(securityEvent => securityEvent.EventType == AshlarSecurityEventTypes.AuthorizationGrantCreated);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(createdEvent.Properties?["grant_id"], Is.EqualTo(grant.Id.ToString("D")));
            Assert.That(createdEvent.Properties?["grant_type"], Is.EqualTo("role"));
            Assert.That(createdEvent.Properties?["grant_value"], Is.EqualTo("reviewer"));
        }
    }

    [Test]
    public async Task RevokeGrantAsyncShouldAuditWhenGrantContextIsUnavailable()
    {
        var auditSink = new RecordingSecurityEventSink();
        var service = new AuthorizationGrantService(new RevokesMissingGrantRepository(), timeProvider: _timeProvider, securityEventSink: auditSink);
        var grantId = Guid.NewGuid();

        var revoked = await service.RevokeGrantAsync(new RevokeAuthorizationGrantRequest(grantId));

        var revokedEvent = auditSink.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.True);
            Assert.That(revokedEvent.UserId, Is.Null);
            Assert.That(revokedEvent.Properties?["grant_id"], Is.EqualTo(grantId.ToString("D")));
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
    public async Task ListGrantsAsyncShouldReturnEmptyForInvalidSearchValues()
    {
        var userId = Guid.NewGuid();
        var service = new AuthorizationGrantService(_repository, new AuthorizationGrantOptions { MaxScopeTypeLength = 1 });

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
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantService(null!));
        Assert.Throws<ArgumentNullException>(() => AuthorizationGrantOptions.Validate(null!));
        Assert.Throws<ArgumentException>(() => _ = new AuthorizationGrantService(_repository, new AuthorizationGrantOptions { MaxRoleLength = 0 }));
        Assert.Throws<ArgumentException>(() => _ = new AuthorizationEvaluator(_repository, new AuthorizationGrantOptions { MaxMetadataLength = 0 }));
    }

    private sealed class FakeRepository : IAuthorizationGrantRepository
    {
        public List<AuthorizationGrant> Grants { get; } = [];
        public ListAuthorizationGrantsRequest? LastListRequest { get; private set; }

        public Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default)
        {
            Grants.Add(grant);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
        {
            LastListRequest = request;
            return Task.FromResult<IReadOnlyList<AuthorizationGrant>>(Grants);
        }

        public Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Grants.FirstOrDefault(grant => grant.Id == grantId));
        }

        public Task<bool> RevokeGrantAsync(Guid grantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
        {
            var grant = Grants.FirstOrDefault(item => item.Id == grantId);
            if (grant?.RevokedAt != null || grant == null)
            {
                return Task.FromResult(false);
            }

            grant.RevokedAt = revokedAt;
            return Task.FromResult(true);
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

        public Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<AuthorizationGrant?>(null);
        }

        public Task<bool> RevokeGrantAsync(Guid grantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }
    }
}
