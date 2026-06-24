using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Authorization;

internal sealed class AuthorizationEvaluatorTests
{
    private FakeTimeProvider _timeProvider;
    private FakeRepository _repository;
    private AuthorizationEvaluator _evaluator;

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        _repository = new FakeRepository();
        _evaluator = new AuthorizationEvaluator(_repository, timeProvider: _timeProvider);
    }

    [Test]
    public async Task EvaluateAsyncShouldMatchGlobalPermission()
    {
        var userId = Guid.NewGuid();
        _repository.Grants.Add(CreateGrant(userId, permission: "posts.edit"));

        var result = await _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Permission: " Posts.Edit "));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(_repository.LastListRequest?.ExactMatch, Is.True);
        }
    }

    [Test]
    public async Task EvaluateAsyncShouldMatchRoleTenantAndScopeExactly()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        _repository.Grants.Add(CreateGrant(userId, tenantId, "project", "abc", role: "reviewer"));

        var result = await _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "Reviewer", TenantId: tenantId, ScopeType: "project", ScopeId: "abc"));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task EvaluateAsyncShouldNotLetScopedGrantApplyGlobally()
    {
        var userId = Guid.NewGuid();
        _repository.Grants.Add(CreateGrant(userId, scopeType: "project", scopeId: "abc", permission: "posts.edit"));

        var result = await _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Permission: "posts.edit"));

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task EvaluateAsyncShouldRejectExpiredRevokedAndWrongTenantGrants()
    {
        var userId = Guid.NewGuid();
        _repository.Grants.Add(CreateGrant(userId, permission: "read", expiresAt: _timeProvider.GetUtcNow().AddSeconds(-1)));
        _repository.Grants.Add(CreateGrant(userId, permission: "read", revokedAt: _timeProvider.GetUtcNow()));
        _repository.Grants.Add(CreateGrant(userId, tenantId: Guid.NewGuid(), permission: "read"));
        _repository.Grants.Add(CreateGrant(userId, permission: "unrelated.permission"));

        var result = await _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Permission: "read"));

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task EvaluateAsyncShouldNotMatchDifferentRoleGrant()
    {
        var userId = Guid.NewGuid();
        _repository.Grants.Add(CreateGrant(userId, role: "reader"));

        var result = await _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Role: "writer"));

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task EvaluateAsyncShouldTreatUnexpiredGrantAsActive()
    {
        var userId = Guid.NewGuid();
        _repository.Grants.Add(CreateGrant(userId, permission: "read", expiresAt: _timeProvider.GetUtcNow().AddSeconds(1)));

        var result = await _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Permission: "read"));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task EvaluateAsyncShouldUseSystemClockWhenNoClockProvided()
    {
        var userId = Guid.NewGuid();
        _repository.Grants.Add(CreateGrant(userId, permission: "read"));
        var evaluator = new AuthorizationEvaluator(_repository);

        var result = await evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Permission: "read"));

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public void IsActiveShouldReturnFalseForRevokedGrantWithoutExpiry()
    {
        var grant = CreateGrant(Guid.NewGuid(), permission: "read", revokedAt: _timeProvider.GetUtcNow());

        Assert.That(grant.IsActive(_timeProvider.GetUtcNow()), Is.False);
    }

    [Test]
    public void IsActiveShouldReturnFalseForRevokedGrantWithFutureExpiry()
    {
        var grant = CreateGrant(
            Guid.NewGuid(),
            permission: "read",
            expiresAt: _timeProvider.GetUtcNow().AddDays(1),
            revokedAt: _timeProvider.GetUtcNow());

        Assert.That(grant.IsActive(_timeProvider.GetUtcNow()), Is.False);
    }

    [Test]
    public void IsActiveShouldReturnFalseWhenGrantExpiresAtCurrentInstant()
    {
        var grant = CreateGrant(Guid.NewGuid(), permission: "read", expiresAt: _timeProvider.GetUtcNow());

        Assert.That(grant.IsActive(_timeProvider.GetUtcNow()), Is.False);
    }

    [Test]
    public void ConstructorShouldRejectNullRepository()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationEvaluator(null!));
    }

    [Test]
    public void EvaluateAsyncShouldValidateRequest()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _evaluator.EvaluateAsync(null!));
        Assert.ThrowsAsync<ArgumentException>(() => _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(Guid.Empty, Permission: "x")));
        Assert.ThrowsAsync<ArgumentException>(() => _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(Guid.NewGuid())));
        Assert.ThrowsAsync<ArgumentException>(() => _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(Guid.NewGuid(), Permission: "p", Role: "r")));
    }

    [Test]
    public async Task EvaluateAsyncShouldFailClosedForInvalidSearchValues()
    {
        var userId = Guid.NewGuid();

        var missingScopeId = await _evaluator.EvaluateAsync(new AuthorizationEvaluationRequest(userId, Permission: "p", ScopeType: "project"));
        var oversizedScope = await new AuthorizationEvaluator(
                _repository,
                new AuthorizationGrantOptions { MaxScopeTypeLength = 1 })
            .EvaluateAsync(new AuthorizationEvaluationRequest(userId, Permission: "p", ScopeType: "project", ScopeId: "1"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingScopeId.Succeeded, Is.False);
            Assert.That(oversizedScope.Succeeded, Is.False);
        }
    }

    private AuthorizationGrant CreateGrant(
        Guid userId,
        Guid? tenantId = null,
        string? scopeType = null,
        string? scopeId = null,
        string? role = null,
        string? permission = null,
        DateTimeOffset? expiresAt = null,
        DateTimeOffset? revokedAt = null)
    {
        return new AuthorizationGrant
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TenantId = tenantId,
            ScopeType = scopeType,
            ScopeId = scopeId,
            Role = role,
            Permission = permission,
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = expiresAt,
            RevokedAt = revokedAt
        };
    }

    private sealed class FakeRepository : IAuthorizationGrantRepository
    {
        public List<AuthorizationGrant> Grants { get; } = [];
        public ListAuthorizationGrantsRequest? LastListRequest { get; private set; }

        public Task CreateGrantAsync(AuthorizationGrant grant, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
        {
            LastListRequest = request;
            var results = Grants
                .Where(grant => grant.UserId == request.UserId)
                .Where(grant => grant.TenantId == request.TenantId)
                .Where(grant => request is { ExactMatch: false, ScopeType: null } || grant.ScopeType == request.ScopeType && grant.ScopeId == request.ScopeId)
                .ToList();
            return Task.FromResult<IReadOnlyList<AuthorizationGrant>>(results);
        }

        public Task<AuthorizationGrant?> GetGrantAsync(Guid grantId, Guid? tenantId, CancellationToken cancellationToken = default) => Task.FromResult<AuthorizationGrant?>(null);

        public Task<bool> RevokeGrantAsync(Guid grantId, Guid? tenantId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) => Task.FromResult(false);
    }
}
