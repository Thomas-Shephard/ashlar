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
            new FreshMfaVerificationProof(userId, null, sessionId, Now, Now.AddYears(10), AccountSecurityActorContext.AdministrationReadProofPurpose), audit);
        var sessions = new Moq.Mock<IAuthenticationSessionRepository>();
        sessions.Setup(x => x.GetSessionAsync(sessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
        { Id = sessionId, UserId = userId, TokenHash = "test", CreatedAt = Now, ExpiresAt = Now.AddYears(10) });
        _context = new AuthorizationGrantMutationContext(new AllowAuthorizer(), sessions.Object);
    }

    private SearchAuthorizationGrantsRequest Authorized(SearchAuthorizationGrantsRequest request) => request with { Actor = _actor };
    private AuthorizationGrantAdministrationLookupRequest Authorized(AuthorizationGrantAdministrationLookupRequest request) => request with { Actor = _actor };

    [Test]
    public async Task SearchAuthorizationGrantsAsyncValidatesScopePagingAndFilters()
    {
        var service = CreateService(new FakeRepository());
        var strictService = CreateService(new FakeRepository(), new AuthorizationGrantOptions { MaxRoleLength = 1 });

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
        var userId = Guid.NewGuid();
        var repository = new FakeRepository
        {
            SearchResults =
            [
                CreateSummary(Guid.NewGuid(), userId),
                CreateSummary(Guid.NewGuid(), userId)
            ]
        };
        var service = CreateService(repository);

        var result = await service.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest
        {
            Tenant = TenantContext.Global,
            UserId = userId,
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
            Assert.That(repository.LastSearchRequest.Limit, Is.EqualTo(AuthorizationGrantAdministrationService.MaximumLimit + 1));
            Assert.That(repository.LastSearchRequest.Offset, Is.EqualTo(3));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncValidatesRoleAndPermissionAfterNormalization()
    {
        var repository = new FakeRepository { SearchResults = [CreateSummary(Guid.NewGuid())] };
        var service = CreateService(repository);

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
        var service = CreateService(repository);

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
            Assert.That(AuthorizationGrantAdministrationService.DeriveStatus(null, null, Now), Is.EqualTo(AuthorizationGrantAdministrationStatus.Active));
            Assert.That(AuthorizationGrantAdministrationService.DeriveStatus(Now, null, Now), Is.EqualTo(AuthorizationGrantAdministrationStatus.Expired));
            Assert.That(AuthorizationGrantAdministrationService.DeriveStatus(Now.AddDays(-1), Now.AddMinutes(-1), Now), Is.EqualTo(AuthorizationGrantAdministrationStatus.Revoked));
        }
    }

    [Test]
    public async Task SearchAuthorizationGrantsAsyncReturnsSafeProjectionWithoutMetadata()
    {
        var repository = new FakeRepository { SearchResults = [CreateSummary(Guid.NewGuid())] };
        var service = CreateService(repository);

        var result = await service.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.Items.Single().Permission, Is.EqualTo("read"));
            Assert.That(typeof(AuthorizationGrantAdministrationSummary).GetProperty("Metadata"), Is.Null);
        }
    }

    [Test]
    public void SearchAuthorizationGrantsAsyncRejectsProviderResultsOutsideRequestedScope()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var service = CreateService(new FakeRepository
        {
            SearchResults = [CreateSingleResult(Guid.NewGuid(), Guid.NewGuid())]
        });

        Assert.ThrowsAsync<InvalidOperationException>(() => service.SearchAuthorizationGrantsAsync(Authorized(
            new SearchAuthorizationGrantsRequest { Tenant = new TenantContext(tenantId), UserId = userId, Limit = 1 })));
    }

    [Test]
    public async Task GetAuthorizationGrantAsyncRejectsMismatchedProviderGrantId()
    {
        var requestedId = Guid.NewGuid();
        var service = CreateService(new FakeRepository
        {
            SingleResult = CreateSingleResult(Guid.NewGuid(), null)
        });

        var result = await service.GetAuthorizationGrantAsync(Authorized(
            new AuthorizationGrantAdministrationLookupRequest(requestedId, TenantContext.Global)));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationGrantNotFound));
    }

    [Test]
    public async Task GetAuthorizationGrantAsyncValidatesAndHidesTenantMismatches()
    {
        var tenantId = Guid.NewGuid();
        var repository = new FakeRepository { SingleResult = CreateSingleResult(Guid.NewGuid(), tenantId) };
        var authorizer = new CapturingAuthorizer();
        var service = CreateService(repository, authorizer: authorizer);

        var invalidGrant = await service.GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(Guid.Empty, TenantContext.Global));
        var missingScope = await service.GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid()));
        var mismatch = await service.GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(repository.SingleResult.Id, new TenantContext(Guid.NewGuid()))));
        var match = await service.GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(repository.SingleResult.Id, new TenantContext(tenantId))));
        var targetDenied = await CreateService(repository, authorizer: new TargetDenyAuthorizer())
            .GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(repository.SingleResult.Id, new TenantContext(tenantId))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(invalidGrant.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(missingScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(mismatch.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationGrantNotFound));
            Assert.That(match.Succeeded, Is.True);
            Assert.That(targetDenied.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationGrantNotFound));
            Assert.That(authorizer.LastContext!.TargetUserId, Is.EqualTo(repository.SingleResult.UserId));
            Assert.That(repository.LastLookupRequest!.Actor, Is.Null);
        }
    }

    [Test]
    public void AddAshlarAuthorizationRegistersAdministrationService()
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => new FakeRepository());
        services.AddAshlarProviderScoped<IAuthorizationGrantAdministrationRepository>(provider => provider.GetRequiredService<FakeRepository>());
        services.AddAshlarProviderScoped(_ => Moq.Mock.Of<IAuthorizationGrantRepository>());
        services.AddAshlarProviderScoped(_ => Moq.Mock.Of<IUserRepository>());
        services.AddAshlarProviderScoped(_ => _context.SessionRepository!);
        services.AddAshlarProviderScoped<IPersistentSecurityEventSink>(_ => new AdminReadTestBoundary.RecordingSink());
        services.AddScoped<IAccountSecurityOperationAuthorizer, AllowAuthorizer>();

        services.AddAshlarAuthorization();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<IAuthorizationGrantAdministrationService>();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(service, Is.TypeOf<AuthorizationGrantAdministrationService>());
            Assert.That(scope.ServiceProvider.GetService<IAuthorizationGrantAdministrationRepository>(), Is.Null);
        }
    }

    [Test]
    public async Task ConstructorsRejectInvalidDependenciesAndOptions()
    {
        var repository = new FakeRepository { SearchResults = [CreateSummary(Guid.NewGuid())] };

        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantAdministrationService(null!, _context.SessionRepository!, new AllowAuthorizer(), new AdminReadTestBoundary.RecordingSink()));
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantAdministrationService(repository, null!, new AllowAuthorizer(), new AdminReadTestBoundary.RecordingSink()));
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantAdministrationService(repository, _context.SessionRepository!, null!, new AdminReadTestBoundary.RecordingSink()));
        Assert.Throws<ArgumentNullException>(() => _ = new AuthorizationGrantAdministrationService(repository, _context.SessionRepository!, new AllowAuthorizer(), null!));
        Assert.Throws<ArgumentException>(() => _ = CreateService(repository, new AuthorizationGrantOptions { MaxRoleLength = 0 }));

        var service = CreateService(repository);
        var result = await service.SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global }));

        Assert.That(result.Succeeded, Is.True);
    }

    private static AuthorizationGrantAdministrationSummary CreateSummary(Guid id, Guid? userId = null)
    {
        return new AuthorizationGrantAdministrationSummary(id, userId ?? Guid.NewGuid(), null, null, null, null, "read", Now, null, null, AuthorizationGrantAdministrationStatus.Active);
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
        public bool ThrowOnSearch { get; init; }
        public bool ThrowOnLookup { get; init; }

        public Task<IReadOnlyList<AuthorizationGrantAdministrationSummary>> SearchAuthorizationGrantsAsync(SearchAuthorizationGrantsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            if (ThrowOnSearch) throw new InvalidOperationException("Provider failed.");
            return Task.FromResult(SearchResults);
        }

        public Task<AuthorizationGrantAdministrationSummary?> GetAuthorizationGrantAsync(AuthorizationGrantAdministrationLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LookupCalls++;
            LastLookupRequest = request;
            if (ThrowOnLookup) throw new InvalidOperationException("Provider failed.");
            return Task.FromResult(SingleResult);
        }
    }

    [Test]
    public void ProviderFailuresAreDurablyAudited()
    {
        var sink = new AdminReadTestBoundary.RecordingSink();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<InvalidOperationException>(() => CreateService(new FakeRepository { ThrowOnSearch = true }, sink: sink)
                .SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global })));
            Assert.ThrowsAsync<InvalidOperationException>(() => CreateService(new FakeRepository { ThrowOnLookup = true }, sink: sink)
                .GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global))));
            Assert.That(sink.Events, Has.Count.EqualTo(2));
            Assert.That(sink.Events, Is.All.Matches<AshlarSecurityEvent>(audit => audit.Outcome == SecurityEventOutcomes.Failure));
        }
    }

    [Test]
    public async Task ReadsRequireVerifiedActorAndHostAuthorization()
    {
        var repository = new FakeRepository { SearchResults = [CreateSummary(Guid.NewGuid())] };
        var request = new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global };
        var missingActor = await CreateService(repository)
            .SearchAuthorizationGrantsAsync(request);
        var mismatchedActor = new AccountSecurityActorContext(_actor.ActorUserId, _actor.ActorTenant, _actor.CurrentSessionId,
            _actor.FreshMfaProof, new AuditContext(Guid.NewGuid()));
        var missingAuditActor = new AccountSecurityActorContext(_actor.ActorUserId, _actor.ActorTenant, _actor.CurrentSessionId,
            _actor.FreshMfaProof, new AuditContext());
        var mismatch = await CreateService(repository)
            .SearchAuthorizationGrantsAsync(request with { Actor = mismatchedActor });
        var missingAudit = await CreateService(repository)
            .SearchAuthorizationGrantsAsync(request with { Actor = missingAuditActor });
        var denied = await CreateService(repository, authorizer: new DenyAuthorizer())
            .SearchAuthorizationGrantsAsync(Authorized(request));
        var missingLookupActor = await CreateService(repository)
            .GetAuthorizationGrantAsync(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global));
        Assert.That(repository.LookupCalls, Is.Zero);
        var deniedLookup = await CreateService(repository, authorizer: new DenyAuthorizer())
            .GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global)));
        Assert.That(repository.LookupCalls, Is.Zero);
        var missingGrant = await CreateService(repository)
            .GetAuthorizationGrantAsync(Authorized(new AuthorizationGrantAdministrationLookupRequest(Guid.NewGuid(), TenantContext.Global)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new[] { missingActor.FailureCode, missingAudit.FailureCode, mismatch.FailureCode,
                missingLookupActor.FailureCode }
                .All(code => code == AshlarFailureCodes.ValidationError), Is.True);
            Assert.That(denied.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationDenied));
            Assert.That(deniedLookup.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationDenied));
            Assert.That(missingGrant.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationGrantNotFound));
        }
    }

    private AuthorizationGrantAdministrationService CreateService(IAuthorizationGrantAdministrationRepository repository,
        AuthorizationGrantOptions? options = null, IAccountSecurityOperationAuthorizer? authorizer = null,
        IPersistentSecurityEventSink? sink = null) =>
        new(repository, _context.SessionRepository!, authorizer ?? _context.Authorizer!,
            sink ?? new AdminReadTestBoundary.RecordingSink(), options, new FakeTimeProvider(Now));

    [Test]
    public async Task ReadsRequireAdminReadProofAndBroadSearchAuthorization()
    {
        var mutationProofActor = new AccountSecurityActorContext(_actor.ActorUserId, _actor.ActorTenant,
            _actor.CurrentSessionId, new FreshMfaVerificationProof(_actor.ActorUserId, _actor.ActorTenant.TenantId,
                _actor.CurrentSessionId, _actor.FreshMfaProof.VerifiedAt, _actor.FreshMfaProof.ExpiresAt,
                AuthorizationGrantService.AdministrationProofPurpose), _actor.Audit);
        var wrongPurpose = await CreateService(new FakeRepository())
            .SearchAuthorizationGrantsAsync(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global, Actor = mutationProofActor });

        var repository = new FakeRepository();
        var selfOnly = await CreateService(repository, authorizer: new SelfOnlyAuthorizer())
            .SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongPurpose.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(selfOnly.FailureCode, Is.EqualTo(AshlarFailureCodes.AuthorizationDenied));
            Assert.That(repository.LastSearchRequest, Is.Null);
        }
    }

    [Test]
    public async Task ReadsDurablyAuditAndFailClosedWhenAuditPersistenceFails()
    {
        var sink = new AdminReadTestBoundary.RecordingSink();
        var result = await CreateService(new FakeRepository(), sink: sink)
            .SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(sink.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AdministrationRead));
            Assert.That(sink.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
        }
        Assert.ThrowsAsync<InvalidOperationException>(() => CreateService(new FakeRepository(), sink: new ThrowingSink())
            .SearchAuthorizationGrantsAsync(Authorized(new SearchAuthorizationGrantsRequest { Tenant = TenantContext.Global })));
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

    private sealed class SelfOnlyAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(context.TargetUserId == context.ActorUserId);
    }

    private sealed class ThrowingSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Audit failed.");
    }
}
