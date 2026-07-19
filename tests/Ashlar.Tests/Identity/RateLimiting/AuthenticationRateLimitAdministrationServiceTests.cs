using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.RateLimiting;

internal sealed class AuthenticationRateLimitAdministrationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly AdminReadTestBoundary ReadBoundary = new(Now);
    private static readonly AdminReadTestBoundary MutationBoundary = new(Now, proofPurpose: IAccountSecurityAdministrationService.ProofPurpose);
    private static readonly string[] ResetAuditPropertyNames = ["bucket_id", "purpose", "reset_status"];

    [Test]
    public async Task SearchBucketsAsyncValidatesRequestAndCapsLimit()
    {
        var repository = new RecordingRepository();
        var service = CreateReader(repository);

        var result = await service.SearchBucketsAsync(ReadBoundary.Actor, TenantContext.Global, false, new SearchAuthenticationRateLimitBucketsRequest { Purpose = "", Limit = 500 });
        var valid = await service.SearchBucketsAsync(ReadBoundary.Actor, TenantContext.Global, false, new SearchAuthenticationRateLimitBucketsRequest { Limit = 500 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(valid.Succeeded, Is.True);
            Assert.That(valid.Value!.Limit, Is.EqualTo(AuthenticationRateLimitAdministrationService.MaximumLimit));
            Assert.That(repository.LastSearchRequest!.Limit, Is.EqualTo(AuthenticationRateLimitAdministrationService.MaximumLimit + 1));
        }
    }

    [Test]
    public async Task SearchBucketsAsyncRejectsInvalidPaging()
    {
        var service = CreateReader(new RecordingRepository());

        var negativeOffset = await service.SearchBucketsAsync(ReadBoundary.Actor, TenantContext.Global, false, new SearchAuthenticationRateLimitBucketsRequest { Offset = -1 });
        var zeroLimit = await service.SearchBucketsAsync(ReadBoundary.Actor, TenantContext.Global, false, new SearchAuthenticationRateLimitBucketsRequest { Limit = 0 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(negativeOffset.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(zeroLimit.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task LookupAndResetValidateRequests()
    {
        var reader = CreateReader(new RecordingRepository());
        var service = CreateMutation(new RecordingRepository());

        var invalidLookup = await reader.GetBucketAsync(ReadBoundary.Actor, TenantContext.Global, false, new AuthenticationRateLimitBucketLookupRequest("", "login"));
        var invalidReset = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, new ResetAuthenticationRateLimitBucketRequest("bucket", "", MutationBoundary.Actor.Audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(invalidLookup.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(invalidReset.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetBucketAsyncReturnsNotFoundForMissingBucket()
    {
        var service = CreateReader(new RecordingRepository { BucketExists = false });

        var result = await service.GetBucketAsync(ReadBoundary.Actor, TenantContext.Global, false, new AuthenticationRateLimitBucketLookupRequest("bucket", "login"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.RateLimitBucketNotFound));
        }
    }

    [Test]
    public async Task ResetBucketAsyncDoesNotMutateWhenPreflightLookupIsMissing()
    {
        var repository = new RecordingRepository { BucketExists = false };

        var result = await CreateMutation(repository).ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false,
            new("missing", "login", MutationBoundary.Actor.Audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
            Assert.That(repository.ResetCalls, Is.Zero);
        }
    }

    [Test]
    public async Task ReaderRejectsInvalidScopeAuthorizationAndMismatchedProviderResults()
    {
        var mismatchedSearch = new RecordingRepository
        {
            SearchResults = [new AuthenticationRateLimitBucketSummary("bucket", "other", 1, Now, Now, null, AuthenticationRateLimitBucketStatus.Active)]
        };
        var mismatchedLookup = new RecordingRepository
        {
            BucketResult = new AuthenticationRateLimitBucketSummary("other-bucket", "other", 1, Now, Now, null, AuthenticationRateLimitBucketStatus.Active)
        };
        var denied = new AdminReadTestBoundary(Now, authorized: false);
        var deniedReader = new AuthenticationRateLimitAdministrationReader(mismatchedSearch, denied.Sessions, denied.Authorizer, denied.Sink, denied.TimeProvider);

        var missingScope = await CreateReader(mismatchedSearch).SearchBucketsAsync(ReadBoundary.Actor, null, false, new());
        var conflictingScope = await CreateReader(mismatchedSearch).GetBucketAsync(ReadBoundary.Actor, TenantContext.Global, true, new("bucket", "login"));
        var deniedResult = await deniedReader.SearchBucketsAsync(denied.Actor, TenantContext.Global, false, new());
        var deniedLookup = await deniedReader.GetBucketAsync(denied.Actor, TenantContext.Global, false, new("bucket", "login"));
        var searchMismatch = await CreateReader(mismatchedSearch).SearchBucketsAsync(ReadBoundary.Actor, TenantContext.Global, false, new() { Purpose = "login" });
        var idMismatch = await CreateReader(mismatchedLookup).GetBucketAsync(ReadBoundary.Actor, TenantContext.Global, false, new("bucket", "other"));
        mismatchedLookup.BucketResult = mismatchedLookup.BucketResult with { BucketId = "bucket", Purpose = "other" };
        var purposeMismatch = await CreateReader(mismatchedLookup).GetBucketAsync(ReadBoundary.Actor, TenantContext.Global, false, new("bucket", "login"));

        Assert.That(new[] { missingScope.Succeeded, conflictingScope.Succeeded, deniedResult.Succeeded, deniedLookup.Succeeded, searchMismatch.Succeeded, idMismatch.Succeeded, purposeMismatch.Succeeded }, Is.All.False);
    }

    [Test]
    public async Task ResetRejectsInvalidScopeAuditActorAndMismatchedLookupWithoutMutation()
    {
        var repository = new RecordingRepository
        {
            BucketResult = new AuthenticationRateLimitBucketSummary("wrong", "wrong", 1, Now, Now, null, AuthenticationRateLimitBucketStatus.Active)
        };
        var service = CreateMutation(repository);
        var request = new ResetAuthenticationRateLimitBucketRequest("bucket", "login", MutationBoundary.Actor.Audit);
        var invalidScope = await service.ResetBucketAsync(MutationBoundary.Actor, null, false, request);
        var conflictingScope = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, true, request);
        var auditMismatch = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false,
            request with { Audit = new AuditContext(Guid.NewGuid()) });
        var missingAuditActor = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false,
            request with { Audit = new AuditContext() });
        var providerMismatch = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new[] { invalidScope, conflictingScope, auditMismatch, missingAuditActor, providerMismatch }.All(result => !result.Succeeded), Is.True);
            Assert.That(repository.ResetCalls, Is.Zero);
        }
    }

    [Test]
    public async Task ResetRejectsHostDenialAndPurposeOnlyProviderMismatch()
    {
        var repository = new RecordingRepository
        {
            BucketResult = new AuthenticationRateLimitBucketSummary("bucket", "wrong", 1, Now, Now, null, AuthenticationRateLimitBucketStatus.Active)
        };
        var denied = new AdminReadTestBoundary(Now, authorized: false,
            proofPurpose: IAccountSecurityAdministrationService.ProofPurpose);
        var composition = new DurableSecurityMutationTestComposition(null, repository);
        var deniedService = new AuthenticationRateLimitAdministrationService(repository,
            new(new FakeTimeProvider(Now), composition.Events, composition.Transactions), denied.Sessions, denied.Authorizer, denied.Sink);
        var deniedResult = await deniedService.ResetBucketAsync(denied.Actor, TenantContext.Global, false,
            new("bucket", "login", denied.Actor.Audit));
        var mismatch = await CreateMutation(repository).ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false,
            new("bucket", "login", MutationBoundary.Actor.Audit));

        Assert.That(new[] { deniedResult.Succeeded, mismatch.Succeeded }, Is.All.False);
    }

    [Test]
    public async Task ResetBucketAsyncAuditsSuccessfulReset()
    {
        var repository = new RecordingRepository { ResetResult = true };
        var sink = new CapturingSecurityEventSink();
        var service = CreateMutation(repository, sink);
        var actorUserId = MutationBoundary.Actor.ActorUserId;
        var audit = MutationBoundary.Actor.Audit with { IpAddress = "127.0.0.1", UserAgent = "tests", CorrelationId = "correlation" };

        var reset = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, new ResetAuthenticationRateLimitBucketRequest("opaque-id", "login", audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(reset.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(sink.Events, Has.Count.EqualTo(1));
            var securityEvent = sink.Events[0];
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimitBucketReset));
            Assert.That(securityEvent.OccurredAt, Is.EqualTo(Now));
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(actorUserId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(securityEvent.UserAgent, Is.EqualTo("tests"));
            Assert.That(securityEvent.CorrelationId, Is.EqualTo("correlation"));
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(securityEvent.Properties, Is.Not.Null);
            AssertSafeResetProperties(securityEvent, "opaque-id", "login", AuthenticationRateLimitBucketResetStatus.Reset);
        }
    }

    [Test]
    public async Task ResetBucketAsyncShouldCommitWhenTransactionProviderIsConfigured()
    {
        var repository = new RecordingRepository { ResetResult = true };
        var transactionProvider = new RecordingTransactionProvider();
        var service = CreateMutation(repository, new CapturingSecurityEventSink(), transactionProvider);

        var result = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, new ResetAuthenticationRateLimitBucketRequest("bucket", "login", MutationBoundary.Actor.Audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(transactionProvider.Transaction.BeginCount, Is.EqualTo(1));
            Assert.That(transactionProvider.Transaction.CommitCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ResetBucketAsyncShouldAllowAtomicRepository()
    {
        var repository = new RecordingRepository { ResetResult = true };
        var service = CreateMutation(repository, new CapturingSecurityEventSink());

        var result = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, new ResetAuthenticationRateLimitBucketRequest("bucket", "login", MutationBoundary.Actor.Audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(repository.ResetCalls, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ResetBucketAsyncAuditsMissingBucket()
    {
        var repository = new RecordingRepository { ResetResult = false };
        var sink = new CapturingSecurityEventSink();
        var service = CreateMutation(repository, sink);
        var audit = MutationBoundary.Actor.Audit with { IpAddress = "127.0.0.1", UserAgent = "tests", CorrelationId = "correlation" };

        var result = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, new ResetAuthenticationRateLimitBucketRequest("missing", "login", audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
            Assert.That(sink.Events, Has.Count.EqualTo(1));
            var securityEvent = sink.Events[0];
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimitBucketReset));
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            AssertSafeResetProperties(securityEvent, "missing", "login", AuthenticationRateLimitBucketResetStatus.NotFound);
        }
    }

    [Test]
    public async Task ResetBucketAsyncReturnsFailedAndAuditsWhenRepositoryThrows()
    {
        var repository = new RecordingRepository { ThrowOnReset = true };
        var sink = new CapturingSecurityEventSink();
        var service = CreateMutation(repository, sink);

        var result = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, new ResetAuthenticationRateLimitBucketRequest("bucket", "login", MutationBoundary.Actor.Audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Failed));
            Assert.That(sink.Events, Has.Count.EqualTo(1));
            var securityEvent = sink.Events[0];
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimitBucketReset));
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            AssertSafeResetProperties(securityEvent, "bucket", "login", AuthenticationRateLimitBucketResetStatus.Failed);
        }
    }

    [Test]
    public async Task ResetBucketAsyncDoesNotAuditInvalidRequest()
    {
        var sink = new CapturingSecurityEventSink();
        var service = CreateMutation(new RecordingRepository(), sink);

        var result = await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, new ResetAuthenticationRateLimitBucketRequest("bucket", "", MutationBoundary.Actor.Audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(sink.Events, Is.Empty);
        }
    }

    [Test]
    public void ResetBucketAsyncAuditSinkFailureFailsCaller()
    {
        var repository = new RecordingRepository { ResetResult = true };
        var sink = new ThrowingSecurityEventSink(new InvalidOperationException("sink failed"));
        var service = CreateMutation(repository, sink);
        var audit = MutationBoundary.Actor.Audit with { IpAddress = "127.0.0.1", UserAgent = "tests", CorrelationId = "correlation" };

        var exception = Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, new ResetAuthenticationRateLimitBucketRequest("opaque-id", "login", audit)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception!.Message, Is.EqualTo("sink failed"));
            AssertSafeResetProperties(sink.Events.Single(), "opaque-id", "login", AuthenticationRateLimitBucketResetStatus.Reset);
        }
    }

    [Test]
    public void ResetBucketAsyncAuditSinkCancellationFailsCallerWhenCallerDidNotCancel()
    {
        var repository = new RecordingRepository { ResetResult = false };
        var sink = new ThrowingSecurityEventSink(new OperationCanceledException("sink canceled"));
        var service = CreateMutation(repository, sink);

        var exception = Assert.ThrowsAsync<OperationCanceledException>(
            async () => await service.ResetBucketAsync(MutationBoundary.Actor, TenantContext.Global, false, new ResetAuthenticationRateLimitBucketRequest("missing", "login", MutationBoundary.Actor.Audit)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception!.Message, Is.EqualTo("sink canceled"));
            AssertSafeResetProperties(sink.Events.Single(), "missing", "login", AuthenticationRateLimitBucketResetStatus.NotFound);
        }
    }

    [Test]
    public void ConstructorValidatesRepository()
    {
        Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(null!, null!));
    }

    [Test]
    public void ConstructorRequiresDurableAuditComposition()
    {
        var repository = new RecordingRepository();
        var transactions = new RecordingTransactionProvider();
        var composition = DurableSecurityMutationTestComposition.Create(transactions, participants: [repository]);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(repository, null!));
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(repository,
                new AuthenticationRateLimitAdministrationServiceDependencies(TransactionProvider: transactions)));
            Assert.Throws<ArgumentNullException>(() => _ = CreateRawService(repository,
                new AuthenticationRateLimitAdministrationServiceDependencies(SecurityEventSink: composition.Events)));
            Assert.Throws<ArgumentException>(() => _ = CreateRawService(repository,
                new AuthenticationRateLimitAdministrationServiceDependencies(SecurityEventSink: new SecurityEventFanOutSink(), TransactionProvider: transactions)));
            Assert.Throws<InvalidOperationException>(() => _ = CreateRawService(repository,
                new AuthenticationRateLimitAdministrationServiceDependencies(SecurityEventSink: new SecurityEventFanOutSink(Mock.Of<IPersistentSecurityEventSink>(), transactionProvider: new RecordingTransactionProvider()), TransactionProvider: transactions)));
            Assert.DoesNotThrow(() => _ = CreateRawService(repository,
                new AuthenticationRateLimitAdministrationServiceDependencies(SecurityEventSink: composition.Events, TransactionProvider: composition.Transactions)));
        }
    }

    [Test]
    public void ReaderConstructorValidatesRepositoryAndDefaultsClock()
    {
        Assert.Throws<ArgumentNullException>(() => _ = CreateRawReader(null!));
        Assert.DoesNotThrow(() => _ = CreateRawReader(new RecordingRepository(), null));
    }

    private static AuthenticationRateLimitAdministrationReader CreateRawReader(IAuthenticationRateLimitAdministrationReaderRepository repository, TimeProvider? timeProvider = null) =>
        new(repository, ReadBoundary.Sessions, ReadBoundary.Authorizer, ReadBoundary.Sink, timeProvider);

    private static AuthenticationRateLimitAdministrationService CreateRawService(IAuthenticationRateLimitAdministrationRepository repository, AuthenticationRateLimitAdministrationServiceDependencies dependencies) =>
        new(repository, dependencies, MutationBoundary.Sessions, MutationBoundary.Authorizer, MutationBoundary.Sink);

    private static AuthenticationRateLimitAdministrationReader CreateReader(IAuthenticationRateLimitAdministrationRepository repository) =>
        CreateRawReader(repository, new FakeTimeProvider(Now));

    private static AuthenticationRateLimitAdministrationService CreateMutation(
        IAuthenticationRateLimitAdministrationRepository repository,
        ISecurityEventSink? sink = null,
        RecordingTransactionProvider? transactions = null)
    {
        var composition = transactions is null
            ? new DurableSecurityMutationTestComposition(sink, repository)
            : DurableSecurityMutationTestComposition.Create(transactions, sink, repository);
        return CreateRawService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now), composition.Events, composition.Transactions));
    }

    [Test]
    public void PublicResultModelsDoNotExposeSensitiveFieldNames()
    {
        var modelTypes = new[]
        {
            typeof(AuthenticationRateLimitBucketSummary),
            typeof(AuthenticationRateLimitBucketSearchResult),
            typeof(AuthenticationRateLimitBucketResetResult)
        };
        var forbidden = new[] { "Key", "Ip", "Email", "UserId", "Token", "Correlation", "Redis" };

        foreach (var type in modelTypes)
        {
            foreach (var property in type.GetProperties())
            {
                Assert.That(forbidden.Any(term => property.Name.Contains(term, StringComparison.OrdinalIgnoreCase)), Is.False, $"{type.Name}.{property.Name}");
            }
        }
    }

    [Test]
    public void AddAshlarIdentityDoesNotRegisterInMemoryAdministrationServiceOrRepository()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<IAuthenticationRateLimitAdministrationRepository>(), Is.Null);
            Assert.That(provider.GetService<IAuthenticationRateLimitAdministrationService>(), Is.Null);
        }
    }

    private sealed class RecordingRepository : IAuthenticationRateLimitAdministrationRepository
    {
        public SearchAuthenticationRateLimitBucketsRequest? LastSearchRequest { get; private set; }

        public bool ResetResult { get; set; }

        public bool ThrowOnReset { get; set; }

        public int ResetCalls { get; private set; }

        public IReadOnlyList<AuthenticationRateLimitBucketSummary> SearchResults { get; set; } = [];

        public AuthenticationRateLimitBucketSummary? BucketResult { get; set; }

        public bool BucketExists { get; set; } = true;

        public Task<IReadOnlyList<AuthenticationRateLimitBucketSummary>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            return Task.FromResult(SearchResults);
        }

        public Task<AuthenticationRateLimitBucketSummary?> GetBucketAsync(AuthenticationRateLimitBucketLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(BucketExists
                ? BucketResult ?? new AuthenticationRateLimitBucketSummary(request.BucketId, request.Purpose, 1, now, now.AddMinutes(1), null, AuthenticationRateLimitBucketStatus.Active)
                : null);
        }

        public Task<bool> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default)
        {
            ResetCalls++;
            if (ThrowOnReset)
            {
                throw new InvalidOperationException("reset failed");
            }

            return Task.FromResult(ResetResult);
        }
    }

    private sealed class CapturingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingSecurityEventSink(Exception exception) : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            throw exception;
        }
    }

    private static void AssertSafeResetProperties(
        AshlarSecurityEvent securityEvent,
        string bucketId,
        string purpose,
        AuthenticationRateLimitBucketResetStatus status)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvent.Properties, Is.Not.Null);
            Assert.That(securityEvent.Properties!.Keys, Is.EquivalentTo(ResetAuditPropertyNames));
            Assert.That(securityEvent.Properties["purpose"], Is.EqualTo(purpose));
            Assert.That(securityEvent.Properties["bucket_id"], Is.EqualTo(bucketId));
            Assert.That(securityEvent.Properties["reset_status"], Is.EqualTo(status.ToString()));
            Assert.That(securityEvent.Properties.Values, Has.None.Contains("127.0.0.1"));
            Assert.That(securityEvent.Properties.Values, Has.None.Contains("correlation"));
            Assert.That(securityEvent.Properties.Keys, Has.None.Contains("ip"));
            Assert.That(securityEvent.Properties.Keys, Has.None.Contains("email"));
            Assert.That(securityEvent.Properties.Keys, Has.None.Contains("user_id"));
            Assert.That(securityEvent.Properties.Keys, Has.None.Contains("redis_key"));
        }
    }
}
