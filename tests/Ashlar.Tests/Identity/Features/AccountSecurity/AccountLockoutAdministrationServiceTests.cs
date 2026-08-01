using Ashlar.Identity.Features.AccountLockout;
using Ashlar.Identity.Models.AccountLockout;
using Ashlar.Auditing;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.AccountSecurity;

internal sealed class AccountLockoutAdministrationServiceTests
{
    private static readonly Guid UserId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid TenantId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 10, 0, 0, TimeSpan.Zero);
    private static readonly AdminReadTestBoundary ReadBoundary = new(Now);
    private static readonly AdminReadTestBoundary MutationBoundary = new(Now, proofPurpose: IAccountSecurityAdministrationService.ProofPurpose);

    private FakeTimeProvider _timeProvider;
    private InMemoryAccountLockoutRepository _repository;
    private RecordingSecurityEventSink _events;
    private DurableSecurityMutationTestComposition _composition;
    private AccountLockoutAdministrationService _service;
    private AccountLockoutAdministrationReader _reader;

    private static AccountLockoutAdministrationService CreateRawService(IAccountLockoutRepository repository, AccountLockoutAdministrationServiceDependencies dependencies) =>
        new(repository, dependencies, MutationBoundary.Sessions, MutationBoundary.Authorizer, MutationBoundary.Sink);

    private static AccountLockoutAdministrationReader CreateRawReader(IAccountLockoutRepository repository, TimeProvider? timeProvider = null) =>
        new(repository, ReadBoundary.Sessions, ReadBoundary.Authorizer, ReadBoundary.Sink, timeProvider);

    [SetUp]
    public void SetUp()
    {
        _timeProvider = new FakeTimeProvider(Now);
        _repository = new InMemoryAccountLockoutRepository();
        _events = new RecordingSecurityEventSink();
        _composition = new DurableSecurityMutationTestComposition(_events, _repository);
        _service = CreateRawService(
            _repository,
            new AccountLockoutAdministrationServiceDependencies(_timeProvider, _composition.Events, _composition.Transactions));
        _reader = CreateRawReader(_repository, _timeProvider);
    }

    [Test]
    public async Task SearchLockoutsAsyncShouldReturnSafePagedSummaries()
    {
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5), version: "secret-version"));
        _repository.Seed(CreateRecord(Guid.NewGuid(), TenantId, new AuthenticationProviderKey(ProviderType.OAuth, "github"), failedAt: Now.AddMinutes(-1), version: "other-version"));

        var result = await _reader.SearchLockoutsAsync(ReadBoundary.Actor, new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(TenantId),
            Limit = 1
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Items, Has.Count.EqualTo(1));
            Assert.That(result.Value?.Limit, Is.EqualTo(1));
            Assert.That(result.Value?.Offset, Is.Zero);
            Assert.That(result.Value?.HasMore, Is.True);
            Assert.That(result.Value?.Items[0].TenantId, Is.EqualTo(TenantId));
            Assert.That(result.Value?.Items[0].IsLockedOut, Is.False);
            Assert.That(result.Value?.Items[0].GetType().GetProperty("Version"), Is.Null);
        }
    }

    [Test]
    public async Task ReadersRejectHostileTenantUserAndProviderResults()
    {
        var provider = AuthenticationProviderKey.Local;
        var request = new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(TenantId),
            UserId = UserId,
            Provider = provider
        };
        var wrongTenant = CreateRecord(UserId, Guid.NewGuid(), provider);
        var wrongUser = CreateRecord(Guid.NewGuid(), TenantId, provider);
        var wrongProvider = CreateRecord(UserId, TenantId, new AuthenticationProviderKey(ProviderType.OAuth, "github"));
        var boundary = new AdminReadTestBoundary(Now);

        Task Search(AccountLockoutRecord record)
        {
            var repository = new Mock<IAccountLockoutRepository>();
            repository.Setup(candidate => candidate.SearchAsync(It.IsAny<SearchAccountLockoutsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync([record]);
            return new AccountLockoutAdministrationReader(repository.Object, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider)
                .SearchLockoutsAsync(boundary.Actor, request);
        }

        Assert.ThrowsAsync<InvalidOperationException>(() => Search(wrongTenant));
        Assert.ThrowsAsync<InvalidOperationException>(() => Search(wrongUser));
        Assert.ThrowsAsync<InvalidOperationException>(() => Search(wrongProvider));
        Assert.ThrowsAsync<InvalidOperationException>(() => Search(null!));

        var lookupRepository = new Mock<IAccountLockoutRepository>();
        lookupRepository.Setup(repository => repository.GetAsync(UserId, TenantId, provider, It.IsAny<CancellationToken>())).ReturnsAsync(wrongUser);
        var reader = new AccountLockoutAdministrationReader(lookupRepository.Object, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider);
        var lookup = await reader.GetLockoutStatusAsync(boundary.Actor, new(UserId, provider, new TenantContext(TenantId)));
        lookupRepository.Setup(repository => repository.GetAsync(UserId, TenantId, provider, It.IsAny<CancellationToken>())).ReturnsAsync(wrongTenant);
        var lookupTenant = await reader.GetLockoutStatusAsync(boundary.Actor, new(UserId, provider, new TenantContext(TenantId)));
        lookupRepository.Setup(repository => repository.GetAsync(UserId, TenantId, provider, It.IsAny<CancellationToken>())).ReturnsAsync(wrongProvider);
        var lookupProvider = await reader.GetLockoutStatusAsync(boundary.Actor, new(UserId, provider, new TenantContext(TenantId)));
        lookupRepository.Setup(repository => repository.GetAsync(UserId, null, provider, It.IsAny<CancellationToken>())).ReturnsAsync(wrongTenant);
        var globalLookupTenant = await reader.GetLockoutStatusAsync(boundary.Actor, new(UserId, provider, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new[] { lookup.Succeeded, lookupTenant.Succeeded, lookupProvider.Succeeded, globalLookupTenant.Succeeded }, Is.All.False);
            Assert.That(boundary.Sink.Events, Has.Count.EqualTo(8));
            Assert.That(boundary.Sink.Events.Select(item => item.Outcome), Is.All.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(boundary.Sink.Events.Take(4).Select(item => item.Properties!["operation"]),
                Is.All.EqualTo(nameof(AccountSecurityOperation.SearchAccountLockouts)));
        }
    }

    [Test]
    public void ReaderRepositoryFailuresAreAuditedAndRethrown()
    {
        var exception = new IOException("provider failed");
        var repository = new Mock<IAccountLockoutRepository>();
        repository.Setup(candidate => candidate.SearchAsync(It.IsAny<SearchAccountLockoutsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ThrowsAsync(exception);
        repository.Setup(candidate => candidate.GetAsync(UserId, TenantId, AuthenticationProviderKey.Local, It.IsAny<CancellationToken>())).ThrowsAsync(exception);
        var boundary = new AdminReadTestBoundary(Now);
        var reader = new AccountLockoutAdministrationReader(repository.Object, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider);

        var search = Assert.ThrowsAsync<IOException>(() => reader.SearchLockoutsAsync(boundary.Actor, new() { Tenant = new(TenantId) }));
        var lookup = Assert.ThrowsAsync<IOException>(() => reader.GetLockoutStatusAsync(boundary.Actor, new(UserId, AuthenticationProviderKey.Local, new(TenantId))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(search, Is.SameAs(exception));
            Assert.That(lookup, Is.SameAs(exception));
            Assert.That(boundary.Sink.Events, Has.Count.EqualTo(2));
            Assert.That(boundary.Sink.Events.Select(item => item.Outcome), Is.All.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(boundary.Sink.Events.Select(item => item.Properties!["operation"]),
                Is.EqualTo(new[] { nameof(AccountSecurityOperation.SearchAccountLockouts), nameof(AccountSecurityOperation.ReadAccountLockout) }));
        }

        repository.Setup(candidate => candidate.SearchAsync(It.IsAny<SearchAccountLockoutsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IReadOnlyList<AccountLockoutRecord>)null!);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Assert.ThrowsAsync<InvalidOperationException>(() => reader.SearchLockoutsAsync(boundary.Actor, new() { Tenant = new(TenantId) })), Is.Not.Null);
            Assert.That(boundary.Sink.Events.Last().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
        }

        var results = new Mock<IReadOnlyList<AccountLockoutRecord>>();
        results.Setup(candidate => candidate.GetEnumerator()).Throws(exception);
        repository.Setup(candidate => candidate.SearchAsync(It.IsAny<SearchAccountLockoutsRequest>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(results.Object);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Assert.ThrowsAsync<IOException>(() => reader.SearchLockoutsAsync(boundary.Actor, new() { Tenant = new(TenantId) })), Is.SameAs(exception));
            Assert.That(boundary.Sink.Events.Last().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
        }

        var auditException = new IOException("audit failed");
        var sink = new Mock<IPersistentSecurityEventSink>();
        sink.Setup(candidate => candidate.RecordAsync(It.IsAny<AshlarSecurityEvent>(), It.IsAny<CancellationToken>())).ThrowsAsync(auditException);
        var failClosedReader = new AccountLockoutAdministrationReader(repository.Object, boundary.Sessions, boundary.Authorizer, sink.Object, boundary.TimeProvider);
        Assert.That(Assert.ThrowsAsync<IOException>(() => failClosedReader.SearchLockoutsAsync(boundary.Actor, new() { Tenant = new(TenantId) })), Is.SameAs(auditException));
    }

    [Test]
    public async Task ResetRejectsHostileLookupWithoutMutation()
    {
        var provider = AuthenticationProviderKey.Local;
        var repository = new Mock<IAccountLockoutRepository>();
        repository.Setup(candidate => candidate.GetAsync(UserId, TenantId, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateRecord(Guid.NewGuid(), TenantId, provider));
        var composition = new DurableSecurityMutationTestComposition(new RecordingSecurityEventSink(), repository.Object);
        var service = CreateRawService(repository.Object,
            new AccountLockoutAdministrationServiceDependencies(_timeProvider, composition.Events, composition.Transactions));

        var hostile = await service.ResetLockoutAsync(MutationBoundary.Actor, new(UserId, provider, new TenantContext(TenantId)));
        repository.Setup(candidate => candidate.GetAsync(UserId, null, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateRecord(UserId, TenantId, provider));
        var hostileGlobal = await service.ResetLockoutAsync(MutationBoundary.Actor, new(UserId, provider, TenantContext.Global));
        repository.Setup(candidate => candidate.GetAsync(UserId, TenantId, provider, It.IsAny<CancellationToken>()))
            .ReturnsAsync((AccountLockoutRecord?)null);
        var missing = await service.ResetLockoutAsync(MutationBoundary.Actor, new(UserId, provider, new TenantContext(TenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new[] { hostile.Succeeded, hostileGlobal.Succeeded }, Is.All.False);
            Assert.That(missing.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.NotFound));
        }
        repository.Verify(candidate => candidate.ResetAsync(It.IsAny<Guid>(), It.IsAny<Guid?>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task ReadersAndResetRejectHostAuthorizationDenial()
    {
        var deniedRead = new AdminReadTestBoundary(Now, authorized: false);
        var readRepository = new Mock<IAccountLockoutRepository>();
        var reader = new AccountLockoutAdministrationReader(readRepository.Object, deniedRead.Sessions, deniedRead.Authorizer, deniedRead.Sink, deniedRead.TimeProvider);
        var search = await reader.SearchLockoutsAsync(deniedRead.Actor, new() { IncludeAllTenants = true });
        var lookup = await reader.GetLockoutStatusAsync(deniedRead.Actor, new(UserId, AuthenticationProviderKey.Local, TenantContext.Global));

        var deniedMutation = new AdminReadTestBoundary(Now, authorized: false,
            proofPurpose: IAccountSecurityAdministrationService.ProofPurpose);
        var service = new AccountLockoutAdministrationService(_repository,
            new(_timeProvider, _composition.Events, _composition.Transactions), deniedMutation.Sessions, deniedMutation.Authorizer, deniedMutation.Sink);
        var reset = await service.ResetLockoutAsync(deniedMutation.Actor, new(UserId, AuthenticationProviderKey.Local, TenantContext.Global));

        Assert.That(new[] { search.Succeeded, lookup.Succeeded, reset.Succeeded }, Is.All.False);
        readRepository.VerifyNoOtherCalls();
    }

    [Test]
    public async Task SuccessfulReadsEmitSuccessAudits()
    {
        var boundary = new AdminReadTestBoundary(Now);
        var reader = new AccountLockoutAdministrationReader(_repository, boundary.Sessions, boundary.Authorizer, boundary.Sink, boundary.TimeProvider);

        await reader.SearchLockoutsAsync(boundary.Actor, new() { IncludeAllTenants = true });
        await reader.GetLockoutStatusAsync(boundary.Actor, new(UserId, AuthenticationProviderKey.Local, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(boundary.Sink.Events.Select(item => item.Outcome), Is.All.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(boundary.Sink.Events.Select(item => item.Properties!["operation"]), Is.EqualTo(new[]
            {
                nameof(AccountSecurityOperation.SearchAccountLockouts), nameof(AccountSecurityOperation.ReadAccountLockout)
            }));
        }
    }

    [Test]
    public async Task LockoutAuthorizationIncludesRequestedProvider()
    {
        AccountSecurityAuthorizationContext? captured = null;
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        authorizer.Setup(candidate => candidate.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>()))
            .Callback<AccountSecurityAuthorizationContext, CancellationToken>((context, _) => captured = context)
            .ReturnsAsync(true);
        var reader = new AccountLockoutAdministrationReader(_repository, ReadBoundary.Sessions, authorizer.Object, ReadBoundary.Sink, _timeProvider);

        await reader.GetLockoutStatusAsync(ReadBoundary.Actor, new(UserId, AuthenticationProviderKey.Local, TenantContext.Global));

        Assert.That(captured?.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
    }

    [Test]
    public async Task SearchLockoutsAsyncShouldFilterActiveLockoutsAfterRepositoryPaging()
    {
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));
        var unlockedUserId = Guid.NewGuid();
        _repository.Seed(CreateRecord(unlockedUserId, TenantId, AuthenticationProviderKey.Local, failedAt: Now.AddMinutes(-1)));
        _repository.Seed(CreateRecord(Guid.NewGuid(), null, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(10)));

        var locked = await _reader.SearchLockoutsAsync(ReadBoundary.Actor, new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(TenantId),
            LockedOut = true,
            Limit = 10
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(locked.Succeeded, Is.True);
            Assert.That(locked.Value?.Items, Has.Count.EqualTo(1));
            Assert.That(locked.Value?.Items.Single().UserId, Is.EqualTo(UserId));
            Assert.That(locked.Value?.Items.Single().IsLockedOut, Is.True);
        }

        var unlocked = await _reader.SearchLockoutsAsync(ReadBoundary.Actor, new SearchAccountLockoutsRequest
        {
            Tenant = new TenantContext(TenantId),
            LockedOut = false,
            Limit = 10
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(unlocked.Succeeded, Is.True);
            Assert.That(unlocked.Value?.Items, Has.Count.EqualTo(1));
            Assert.That(unlocked.Value?.Items.Single().UserId, Is.EqualTo(unlockedUserId));
            Assert.That(unlocked.Value?.HasMore, Is.False);
        }
    }

    [Test]
    public async Task GetLockoutStatusAsyncShouldReturnCurrentStatusOrUnlockedStatusWhenMissing()
    {
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));

        var existing = await _reader.GetLockoutStatusAsync(ReadBoundary.Actor, new AccountLockoutStatusRequest(UserId, AuthenticationProviderKey.Local, new TenantContext(TenantId)));
        var result = await _reader.GetLockoutStatusAsync(ReadBoundary.Actor, new AccountLockoutStatusRequest(UserId, AuthenticationProviderKey.Local, new TenantContext(TenantId)));
        await _service.ResetLockoutAsync(MutationBoundary.Actor, new ResetAccountLockoutRequest(UserId, AuthenticationProviderKey.Local, new TenantContext(TenantId)));
        var missing = await _reader.GetLockoutStatusAsync(ReadBoundary.Actor, new AccountLockoutStatusRequest(UserId, AuthenticationProviderKey.Local, new TenantContext(TenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(existing.Succeeded, Is.True);
            Assert.That(existing.Value?.FailedAttemptCount, Is.EqualTo(3));
            Assert.That(existing.Value?.IsLockedOut, Is.True);
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(result.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(missing.Value?.FailedAttemptCount, Is.Zero);
            Assert.That(missing.Value?.IsLockedOut, Is.False);
        }
    }

    [Test]
    public async Task ResetLockoutAsyncShouldClearOnlyAutomaticLockoutState()
    {
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));

        var reset = await _service.ResetLockoutAsync(MutationBoundary.Actor, new ResetAccountLockoutRequest(UserId, AuthenticationProviderKey.Local, new TenantContext(TenantId)));
        var secondReset = await _service.ResetLockoutAsync(MutationBoundary.Actor, new ResetAccountLockoutRequest(UserId, AuthenticationProviderKey.Local, new TenantContext(TenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(reset.Succeeded, Is.True);
            Assert.That(reset.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.Reset));
            Assert.That(reset.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(reset.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(reset.Value?.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(secondReset.Succeeded, Is.True);
            Assert.That(secondReset.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.NotFound));
            Assert.That(secondReset.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(secondReset.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(secondReset.Value?.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
        }
    }

    [Test]
    public async Task ResetLockoutAsyncShouldCommitWhenTransactionProviderIsConfigured()
    {
        var transactionProvider = new RecordingTransactionProvider();
        var composition = DurableSecurityMutationTestComposition.Create(transactionProvider, _events, _repository);
        _repository.Seed(CreateRecord(UserId, TenantId, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));
        var service = CreateRawService(
            _repository,
            new AccountLockoutAdministrationServiceDependencies(_timeProvider, composition.Events, composition.Transactions));

        var result = await service.ResetLockoutAsync(MutationBoundary.Actor,
            new ResetAccountLockoutRequest(UserId, AuthenticationProviderKey.Local, new TenantContext(TenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(transactionProvider.Transaction.BeginCount, Is.EqualTo(1));
            Assert.That(transactionProvider.Transaction.CommitCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ResetLockoutAsyncShouldEmitSafeAuditEventWhenStateIsCleared()
    {
        var actorId = MutationBoundary.Actor.ActorUserId;

        var actor = WithAudit(MutationBoundary.Actor, MutationBoundary.Actor.Audit with
        {
            IpAddress = "203.0.113.10",
            UserAgent = "admin-agent",
            CorrelationId = "corr-reset"
        });
        var provider = new AuthenticationProviderKey(ProviderType.OAuth, "github");
        _repository.Seed(CreateRecord(UserId, TenantId, provider, lockedUntil: Now.AddMinutes(5), version: "secret-version"));

        var result = await _service.ResetLockoutAsync(actor,
            new ResetAccountLockoutRequest(UserId, provider, new TenantContext(TenantId), "support reset"));

        var securityEvent = _events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.Reset));
            Assert.That(result.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(result.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(result.Value?.Provider, Is.EqualTo(provider));
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.AccountLockoutReset));
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(securityEvent.UserId, Is.EqualTo(UserId));
            Assert.That(securityEvent.TenantId, Is.EqualTo(TenantId));
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(actorId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo("203.0.113.10"));
            Assert.That(securityEvent.UserAgent, Is.EqualTo("admin-agent"));
            Assert.That(securityEvent.CorrelationId, Is.EqualTo("corr-reset"));
            Assert.That(securityEvent.Provider, Is.EqualTo(provider));
            Assert.That(securityEvent.Properties?["lockout_state_cleared"], Is.EqualTo("true"));
            Assert.That(securityEvent.Properties?["tenant_scope"], Is.EqualTo("tenant"));
            Assert.That(securityEvent.Properties?["tenant_id"], Is.EqualTo(TenantId.ToString()));
            Assert.That(securityEvent.Properties?["reason"], Is.EqualTo("support reset"));
            Assert.That(securityEvent.Properties?.ContainsKey("version"), Is.False);
            Assert.That(securityEvent.Properties?.ContainsKey("password"), Is.False);
        }
    }

    [Test]
    public async Task ResetLockoutAsyncShouldEmitNoOpAuditEventWhenStateIsMissing()
    {
        var result = await _service.ResetLockoutAsync(MutationBoundary.Actor,
            new ResetAccountLockoutRequest(UserId, AuthenticationProviderKey.Local, new TenantContext(TenantId)));

        var securityEvent = _events.Events.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.NotFound));
            Assert.That(result.Value?.UserId, Is.EqualTo(UserId));
            Assert.That(result.Value?.TenantId, Is.EqualTo(TenantId));
            Assert.That(result.Value?.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.AccountLockoutReset));
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(securityEvent.UserId, Is.EqualTo(UserId));
            Assert.That(securityEvent.TenantId, Is.EqualTo(TenantId));
            Assert.That(securityEvent.Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(CreateAudit().ActorUserId));
            Assert.That(securityEvent.Properties?["lockout_state_cleared"], Is.EqualTo("false"));
            Assert.That(securityEvent.Properties?.ContainsKey("reason"), Is.False);
        }
    }

    [Test]
    public async Task OperationsShouldValidateInputs()
    {
        var unknownProvider = new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "unknown");
        var invalidSearches = new[]
        {
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Limit = 0 },
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Offset = -1 },
            new SearchAccountLockoutsRequest(),
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, IncludeAllTenants = true },
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, UserId = Guid.Empty },
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Provider = default(AuthenticationProviderKey) },
            new SearchAccountLockoutsRequest { Tenant = TenantContext.Global, Provider = unknownProvider }
        };

        foreach (var request in invalidSearches)
        {
            var result = await _reader.SearchLockoutsAsync(ReadBoundary.Actor, request);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => _reader.SearchLockoutsAsync(ReadBoundary.Actor, null!));
            Assert.That((await _reader.GetLockoutStatusAsync(ReadBoundary.Actor, new AccountLockoutStatusRequest(Guid.Empty, AuthenticationProviderKey.Local, TenantContext.Global))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _reader.GetLockoutStatusAsync(ReadBoundary.Actor, new AccountLockoutStatusRequest(UserId, default, TenantContext.Global))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _reader.GetLockoutStatusAsync(ReadBoundary.Actor, new AccountLockoutStatusRequest(UserId, unknownProvider, TenantContext.Global))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _reader.GetLockoutStatusAsync(ReadBoundary.Actor, new AccountLockoutStatusRequest(UserId, AuthenticationProviderKey.Local, null!))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _service.ResetLockoutAsync(MutationBoundary.Actor, new ResetAccountLockoutRequest(Guid.Empty, AuthenticationProviderKey.Local, TenantContext.Global))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _service.ResetLockoutAsync(MutationBoundary.Actor, new ResetAccountLockoutRequest(UserId, default, TenantContext.Global))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _service.ResetLockoutAsync(MutationBoundary.Actor, new ResetAccountLockoutRequest(UserId, unknownProvider, TenantContext.Global))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _service.ResetLockoutAsync(MutationBoundary.Actor, new ResetAccountLockoutRequest(UserId, AuthenticationProviderKey.Local, null!))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That((await _service.ResetLockoutAsync(MutationBoundary.Actor, new ResetAccountLockoutRequest(UserId, AuthenticationProviderKey.Local, TenantContext.Global, new string('x', 513)))).FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(null!, null!));
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(_repository, null!));
            Assert.That(_events.Events, Is.Empty);
        }
    }

    [Test]
    public void LookupAndResetRejectNullInputsBeforeRepositoryAccess()
    {
        var repository = new Mock<IAccountLockoutRepository>();
        var reader = CreateRawReader(repository.Object);
        var composition = new DurableSecurityMutationTestComposition(new RecordingSecurityEventSink(), repository.Object);
        var service = CreateRawService(repository.Object,
            new AccountLockoutAdministrationServiceDependencies(_timeProvider, composition.Events, composition.Transactions));
        var lookup = new AccountLockoutStatusRequest(UserId, AuthenticationProviderKey.Local, TenantContext.Global);
        var reset = new ResetAccountLockoutRequest(UserId, AuthenticationProviderKey.Local, TenantContext.Global);

        Assert.ThrowsAsync<ArgumentNullException>(() => reader.GetLockoutStatusAsync(null!, lookup));
        Assert.ThrowsAsync<ArgumentNullException>(() => reader.GetLockoutStatusAsync(ReadBoundary.Actor, null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => service.ResetLockoutAsync(null!, reset));
        Assert.ThrowsAsync<ArgumentNullException>(() => service.ResetLockoutAsync(MutationBoundary.Actor, null!));
        repository.VerifyNoOtherCalls();
    }

    [Test]
    public void ConstructorRequiresDurableAuditComposition()
    {
        var transactions = new RecordingTransactionProvider();
        var composition = DurableSecurityMutationTestComposition.Create(transactions, participants: [_repository]);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(_repository,
                new AccountLockoutAdministrationServiceDependencies(TransactionProvider: transactions)));
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(_repository,
                new AccountLockoutAdministrationServiceDependencies(SecurityEventSink: composition.Events)));
            Assert.Throws<ArgumentException>(() => _ = CreateRawService(_repository,
                new AccountLockoutAdministrationServiceDependencies(SecurityEventSink: new SecurityEventFanOutSink(), TransactionProvider: transactions)));
            Assert.Throws<InvalidOperationException>(() => _ = CreateRawService(_repository,
                new AccountLockoutAdministrationServiceDependencies(SecurityEventSink: new SecurityEventFanOutSink(Mock.Of<IPersistentSecurityEventSink>(), transactionProvider: new RecordingTransactionProvider()), TransactionProvider: transactions)));
            Assert.DoesNotThrow(() => _ = CreateRawService(_repository,
                new AccountLockoutAdministrationServiceDependencies(SecurityEventSink: composition.Events, TransactionProvider: composition.Transactions)));
        }
    }

    [Test]
    public void LockoutRequestsDoNotEmbedActorContext()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(typeof(AccountLockoutStatusRequest).GetProperties().Select(property => property.PropertyType),
                Does.Not.Contain(typeof(AccountSecurityActorContext)));
            Assert.That(typeof(ResetAccountLockoutRequest).GetProperties().Select(property => property.PropertyType),
                Does.Not.Contain(typeof(AccountSecurityActorContext)));
            Assert.That(typeof(ResetAccountLockoutRequest).GetProperty("Audit"), Is.Null);
        }
    }

    [Test]
    public void ReaderConstructorValidatesRepositoryAndDefaultsClock()
    {
        Assert.Throws<ArgumentNullException>(() => _ = CreateRawReader(null!));
        Assert.DoesNotThrow(() => _ = CreateRawReader(_repository, null));
    }

    [Test]
    public async Task StatusAndResetShouldUseExplicitGlobalTenantScope()
    {
        _repository.Seed(CreateRecord(UserId, null, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));
        var secondUserId = Guid.NewGuid();
        _repository.Seed(CreateRecord(secondUserId, null, AuthenticationProviderKey.Local, lockedUntil: Now.AddMinutes(5)));

        var status = await _reader.GetLockoutStatusAsync(ReadBoundary.Actor, new AccountLockoutStatusRequest(UserId, AuthenticationProviderKey.Local, TenantContext.Global));
        var secondStatus = await _reader.GetLockoutStatusAsync(ReadBoundary.Actor, new AccountLockoutStatusRequest(secondUserId, AuthenticationProviderKey.Local, TenantContext.Global));
        var reset = await _service.ResetLockoutAsync(MutationBoundary.Actor, new ResetAccountLockoutRequest(UserId, AuthenticationProviderKey.Local, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(status.Succeeded, Is.True);
            Assert.That(status.Value?.TenantId, Is.Null);
            Assert.That(status.Value?.IsLockedOut, Is.True);
            Assert.That(secondStatus.Succeeded, Is.True);
            Assert.That(secondStatus.Value?.TenantId, Is.Null);
            Assert.That(secondStatus.Value?.IsLockedOut, Is.True);
            Assert.That(reset.Succeeded, Is.True);
            Assert.That(reset.Value?.Status, Is.EqualTo(AccountLockoutResetStatus.Reset));
            Assert.That(reset.Value?.TenantId, Is.Null);
            Assert.That(_events.Events.Single().TenantId, Is.Null);
            Assert.That(_events.Events.Single().Properties?["tenant_scope"], Is.EqualTo("global"));
            Assert.That(_events.Events.Single().Properties?.ContainsKey("tenant_id"), Is.False);
        }
    }

    private static AccountLockoutRecord CreateRecord(
        Guid userId,
        Guid? tenantId,
        AuthenticationProviderKey provider,
        DateTimeOffset? failedAt = null,
        DateTimeOffset? lockedUntil = null,
        string version = "version")
    {
        var lastFailedAt = failedAt ?? Now.AddMinutes(-5);
        return new AccountLockoutRecord(
            userId,
            tenantId,
            provider,
            3,
            lastFailedAt.AddMinutes(-1),
            lastFailedAt,
            lockedUntil,
            version);
    }

    private static AuditContext CreateAudit()
    {
        return MutationBoundary.Actor.Audit with { IpAddress = "203.0.113.10", UserAgent = "admin-agent", CorrelationId = "corr-reset" };
    }

    private static AccountSecurityActorContext WithAudit(AccountSecurityActorContext actor, AuditContext audit) =>
        new(actor.ActorUserId, actor.ActorTenant, actor.CurrentSessionId, actor.FreshMfaProof, audit);

    private sealed class InMemoryAccountLockoutRepository : IAccountLockoutRepository
    {
        private readonly List<AccountLockoutRecord> _records = [];

        public void Seed(AccountLockoutRecord record)
        {
            _records.Add(record);
        }

        public Task<IReadOnlyList<AccountLockoutRecord>> SearchAsync(SearchAccountLockoutsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            IEnumerable<AccountLockoutRecord> records = _records;
            if (request.Tenant is { } tenant)
            {
                records = records.Where(record => record.TenantId == tenant.TenantId);
            }

            if (request.UserId is { } userId)
            {
                records = records.Where(record => record.UserId == userId);
            }

            if (request.Provider is { } provider)
            {
                records = records.Where(record => record.Provider == provider);
            }

            if (request.LockedOut is { } lockedOut)
            {
                records = records.Where(record => (record.LockedUntil is { } lockedUntil && lockedUntil > now) == lockedOut);
            }

            return Task.FromResult<IReadOnlyList<AccountLockoutRecord>>(records
                .OrderByDescending(record => record.LastFailedAt)
                .Skip(request.Offset)
                .Take(request.Limit)
                .ToList()
                .AsReadOnly());
        }

        public Task<AccountLockoutRecord?> GetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_records.SingleOrDefault(record => record.UserId == userId && record.TenantId == tenantId && record.Provider == provider));
        }

        public Task<AccountLockoutRecordUpdate> RecordFailureAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, DateTimeOffset failedAt, int failureThreshold, TimeSpan lockoutDuration, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<bool> ResetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default)
        {
            var removed = _records.RemoveAll(record => record.UserId == userId && record.TenantId == tenantId && record.Provider == provider);
            return Task.FromResult(removed > 0);
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
}
