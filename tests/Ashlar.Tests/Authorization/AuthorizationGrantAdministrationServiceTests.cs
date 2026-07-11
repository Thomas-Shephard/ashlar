using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Auditing;
using Moq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Authorization;

internal sealed class AuthorizationGrantAdministrationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 2, 12, 0, 0, TimeSpan.Zero);
    private AccountSecurityActorContext _actor = null!;
    private AuthorizationGrantMutationContext _context = null!;

    [SetUp]
    public void SetUp()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var audit = new AuditContext(userId);
        _actor = new AccountSecurityActorContext(userId, TenantContext.Global, sessionId,
            new FreshMfaVerificationProof(userId, null, sessionId, Now, Now.AddYears(10), AuthorizationGrantService.AdministrationProofPurpose), audit);
        var sessions = new Moq.Mock<IAuthenticationSessionRepository>();
        sessions.Setup(x => x.GetSessionAsync(sessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
        { Id = sessionId, UserId = userId, TokenHash = "test", CreatedAt = Now, ExpiresAt = Now.AddYears(10) });
        _context = new AuthorizationGrantMutationContext(new AllowAuthorizer(), sessions.Object);
    }

    private SearchAuthorizationGrantsRequest Authorized(SearchAuthorizationGrantsRequest request) => request with { Actor = _actor, Audit = _actor.Audit };
    private AuthorizationGrantAdministrationLookupRequest Authorized(AuthorizationGrantAdministrationLookupRequest request) => request with { Actor = _actor, Audit = _actor.Audit };

    [Test]
    public async Task SearchAuthorizationGrantsAsyncValidatesScopePagingAndFilters()
    {
        var service = new AuthorizationGrantAdministrationService(new FakeRepository(), timeProvider: new FakeTimeProvider(Now), authorizationContext: _context);
        var strictService = new AuthorizationGrantAdministrationService(new FakeRepository(), new AuthorizationGrantOptions { MaxRoleLength = 1 }, new FakeTimeProvider(Now), _context);

        var missingScope = await service.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest());
        var mixedScope = await service.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true });
        var missingScopeId = await service.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, ScopeType = "project" });
        var emptyUser = await service.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, UserId = Guid.Empty });
        var roleAndPermission = await service.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Role = "admin", Permission = "read" });
        var negativeOffset = await service.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Offset = -1 });
        var zeroLimit = await service.SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Limit = 0 });
        var oversizedRole = await strictService.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Role = "admin" }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(mixedScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(missingScopeId.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(emptyUser.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(roleAndPermission.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(negativeOffset.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(zeroLimit.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(oversizedRole.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncNormalizesFiltersAndCapsPageSize()
    {
        var repository = new FakeRepository
        {
            SearchResults =
            [
                CreateSummary(Guid.NewGuid()),
                CreateSummary(Guid.NewGuid())
            ]
        };
        var service = new AuthorizationGrantAdministrationService(repository, timeProvider: new FakeTimeProvider(Now), authorizationContext: _context);

        var result = await service.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest
        {
            Tenant = TenantContext.Global,
            UserId = Guid.NewGuid(),
            Role = " Admin ",
            ScopeType = " Project ",
            ScopeId = " Alpha ",
            Limit = 500,
            Offset = 3
        }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.Limit, Is.EqualTo(AuthorizationGrantAdministrationService.MaximumLimit));
            Assert.That(result.Value.HasMore, Is.False);
            Assert.That(repository.LastSearchRequest!.Role, Is.EqualTo("admin"));
            Assert.That(repository.LastSearchRequest.ScopeType, Is.EqualTo("project"));
            Assert.That(repository.LastSearchRequest.ScopeId, Is.EqualTo("alpha"));
            Assert.That(repository.LastSearchRequest.Actor, Is.Null);
            Assert.That(repository.LastSearchRequest.Audit, Is.Null);
            Assert.That(repository.LastSearchRequest.Limit, Is.EqualTo(AuthorizationGrantAdministrationService.MaximumLimit + 1));
            Assert.That(repository.LastSearchRequest.Offset, Is.EqualTo(3));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncValidatesRoleAndPermissionAfterNormalization()
    {
        var repository = new FakeRepository { SearchResults = [CreateSummary(Guid.NewGuid())] };
        var service = new AuthorizationGrantAdministrationService(repository, timeProvider: new FakeTimeProvider(Now), authorizationContext: _context);

        var whitespaceRole = await service.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest
        {
            Tenant = TenantContext.Global,
            Role = " ",
            Permission = " Read "
        }));
        var combined = await service.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest
        {
            Tenant = TenantContext.Global,
            Role = "admin",
            Permission = "read"
        }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(whitespaceRole.Succeeded, Is.True);
            Assert.That(repository.LastSearchRequest!.Role, Is.Null);
            Assert.That(repository.LastSearchRequest.Permission, Is.EqualTo("read"));
            Assert.That(combined.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncUsesLimitPlusOneForHasMore()
    {
        var repository = new FakeRepository
        {
            SearchResults =
            [
                CreateSummary(Guid.NewGuid()),
                CreateSummary(Guid.NewGuid())
            ]
        };
        var service = new AuthorizationGrantAdministrationService(repository, timeProvider: new FakeTimeProvider(Now), authorizationContext: _context);

        var result = await service.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Limit = 1 }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Items, Has.Count.EqualTo(1));
            Assert.That(result.Value.HasMore, Is.True);
        }
    }

    [Test]
    public void DeriveStatusPrioritizesRevokedThenExpiredThenActive()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AuthorizationGrantAdministrationService.DeriveStatus(Now.AddDays(1), null, Now), Is.EqualTo(AuthorizationGrantAdministrationStatus.Active));
            Assert.That(AuthorizationGrantAdministrationService.DeriveStatus(Now, null, Now), Is.EqualTo(AuthorizationGrantAdministrationStatus.Expired));
            Assert.That(AuthorizationGrantAdministrationService.DeriveStatus(Now.AddDays(-1), Now.AddMinutes(-1), Now), Is.EqualTo(AuthorizationGrantAdministrationStatus.Revoked));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncReturnsSafeProjectionWithoutMetadata()
    {
        var repository = new FakeRepository { SearchResults = [CreateSummary(Guid.NewGuid())] };
        var service = new AuthorizationGrantAdministrationService(repository, timeProvider: new FakeTimeProvider(Now), authorizationContext: _context);

        var result = await service.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.Items.Single().Permission, Is.EqualTo("read"));
            Assert.That(typeof(AuthorizationGrantAdministrationSummary).GetProperty("Metadata"), Is.Null);
        }
    }

    [Test]
    public async Task GetAuthorizationGrantAsyncValidatesAndHidesTenantMismatches()
    {
        var tenantId = Guid.NewGuid();
        var repository = new FakeRepository { SingleResult = CreateSingleResult(Guid.NewGuid(), tenantId) };
        var authorizer = new CapturingAuthorizer();
        var service = new AuthorizationGrantAdministrationService(repository, timeProvider: new FakeTimeProvider(Now),
            authorizationContext: new AuthorizationGrantMutationContext(authorizer, _context.SessionRepository));

        var invalidGrant = await service.GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(Guid.Empty, TenantContext.Global));
        var missingScope = await service.GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid()));
        var mismatch = await service.GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(repository.SingleResult.Id, new TenantContext(Guid.NewGuid()))));
        var match = await service.GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(repository.SingleResult.Id, new TenantContext(tenantId))));
        var targetDenied = await new AuthorizationGrantAdministrationService(repository, timeProvider: new FakeTimeProvider(Now),
                authorizationContext: new AuthorizationGrantMutationContext(new TargetDenyAuthorizer(), _context.SessionRepository))
            .GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(repository.SingleResult.Id, new TenantContext(tenantId))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(invalidGrant.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(missingScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(mismatch.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationGrantNotFound));
            Assert.That(match.Succeeded, Is.True);
            Assert.That(targetDenied.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(authorizer.LastContext!.TargetUserId, Is.EqualTo(repository.SingleResult.UserId));
            Assert.That(repository.LastLookupRequest!.Actor, Is.Null);
            Assert.That(repository.LastLookupRequest.Audit, Is.Null);
        }
    }

    [Test]
    public void AddAshlarAuthorizationRegistersAdministrationService()
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => new FakeRepository());
        services.AddScoped<IAuthorizationGrantAdministrationRepository>(provider => provider.GetRequiredService<FakeRepository>());
        services.AddScoped(_ => Moq.Mock.Of<IAuthorizationGrantRepository>());
        services.AddScoped(_ => Moq.Mock.Of<IUserRepository>());

        services.AddAshlarAuthorization();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<IAuthorizationGrantAdministrationService>();

        Assert.That(service, Is.TypeOf<AuthorizationGrantAdministrationService>());
    }

    [Test]
    public async Task ConstructorsRejectInvalidDependenciesAndOptions()
    {
        var repository = new FakeRepository { SearchResults = [CreateSummary(Guid.NewGuid())] };

        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantAdministrationService(null!));
        Assert.Throws<ArgumentException>(() => _ = new AuthorizationGrantAdministrationService(repository, new AuthorizationGrantOptions { MaxRoleLength = 0 }));

        var service = new AuthorizationGrantAdministrationService(repository, timeProvider: null, authorizationContext: _context);
        var result = await service.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global }));

        Assert.That(result.Succeeded, Is.True);
    }

    private static AuthorizationGrantAdministrationSummary CreateSummary(Guid id)
    {
        return new AuthorizationGrantAdministrationSummary(id, Guid.NewGuid(), null, null, null, null, "read", Now, null, null, AuthorizationGrantAdministrationStatus.Active);
    }

    private static AuthorizationGrantAdministrationSummary CreateSingleResult(Guid id, Guid? tenantId)
    {
        return new AuthorizationGrantAdministrationSummary(id, Guid.NewGuid(), tenantId, null, null, null, "read", Now, null, null, AuthorizationGrantAdministrationStatus.Active);
    }

    private sealed class FakeRepository : IAuthorizationGrantAdministrationRepository
    {
        public IReadOnlyList<AuthorizationGrantAdministrationSummary> SearchResults { get; init; } = [];
        public AuthorizationGrantAdministrationSummary? SingleResult { get; init; }
        public SearchAuthorizationGrantsRequest? LastSearchRequest { get; private set; }
        public AuthorizationGrantAdministrationLookupRequest? LastLookupRequest { get; private set; }
        public int LookupCalls { get; private set; }

        public Task<IReadOnlyList<AuthorizationGrantAdministrationSummary>> SearchAuthorizationGrantsAsync(SearchAuthorizationGrantsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            return Task.FromResult(SearchResults);
        }

        public Task<AuthorizationGrantAdministrationSummary?> GetAuthorizationGrantAsync(AuthorizationGrantAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LookupCalls++;
            LastLookupRequest = request;
            return Task.FromResult(SingleResult);
        }
    }

    [Test]
    public async Task ReadsRequireVerifiedActorAndHostAuthorization()
    {
        var repository = new FakeRepository { SearchResults = [CreateSummary(Guid.NewGuid())] };
        var request = new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global };
        var missingActor = await new AuthorizationGrantAdministrationService(repository)
            .SearchAuthorizationGrantsAsync(request);
        var missingActorWithAudit = await new AuthorizationGrantAdministrationService(repository, authorizationContext: _context)
            .SearchAuthorizationGrantsAsync(request with { Audit = _actor.Audit });
        var missingAudit = await new AuthorizationGrantAdministrationService(repository, authorizationContext: _context)
            .SearchAuthorizationGrantsAsync(request with { Actor = _actor });
        var mismatch = await new AuthorizationGrantAdministrationService(repository, authorizationContext: _context)
            .SearchAuthorizationGrantsAsync(request with { Actor = _actor, Audit = new AuditContext(Guid.NewGuid()) });
        var missingAuditActor = await new AuthorizationGrantAdministrationService(repository, authorizationContext: _context)
            .SearchAuthorizationGrantsAsync(request with { Actor = _actor, Audit = new AuditContext() });
        var denied = await new AuthorizationGrantAdministrationService(repository, authorizationContext:
                new AuthorizationGrantMutationContext(new DenyAuthorizer(), _context.SessionRepository))
            .SearchAuthorizationGrantsAsync(Authorized(request));
        var missingLookupActor = await new AuthorizationGrantAdministrationService(repository, authorizationContext: _context)
            .GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));
        Assert.That(repository.LookupCalls, Is.Zero);
        var missingSession = await new AuthorizationGrantAdministrationService(repository, authorizationContext:
                new AuthorizationGrantMutationContext(new AllowAuthorizer()))
            .SearchAuthorizationGrantsAsync(Authorized(request));
        var missingAuthorizer = await new AuthorizationGrantAdministrationService(repository, authorizationContext:
                new AuthorizationGrantMutationContext(SessionRepository: _context.SessionRepository))
            .SearchAuthorizationGrantsAsync(Authorized(request));
        var deniedLookup = await new AuthorizationGrantAdministrationService(repository, authorizationContext:
                new AuthorizationGrantMutationContext(new DenyAuthorizer(), _context.SessionRepository))
            .GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global)));
        Assert.That(repository.LookupCalls, Is.Zero);
        var missingGrant = await new AuthorizationGrantAdministrationService(repository, authorizationContext: _context)
            .GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new[] { missingActor.FailureCode, missingActorWithAudit.FailureCode, missingAudit.FailureCode, mismatch.FailureCode, missingAuditActor.FailureCode, denied.FailureCode,
                missingLookupActor.FailureCode, missingSession.FailureCode, missingAuthorizer.FailureCode }
                .All(code => code == AshlarFailureCodes.ValidationError), Is.True);
            Assert.That(deniedLookup.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(missingGrant.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationGrantNotFound));
        }
    }

    private sealed class AllowAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) => ValueTask.FromResult(true);
    }

    private sealed class DenyAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) => ValueTask.FromResult(false);
    }

    private sealed class CapturingAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public AccountSecurityAuthorizationContext? LastContext { get; private set; }
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default)
        {
            LastContext = context;
            return ValueTask.FromResult(true);
        }
    }

    private sealed class TargetDenyAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(context.TargetUserId == Guid.Empty);
    }
}
