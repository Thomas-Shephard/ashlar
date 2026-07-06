using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Identity.RateLimiting;

internal sealed class AuthenticationRateLimitAdministrationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] ResetAuditPropertyNames = ["bucket_id", "purpose", "reset_status"];

    [Test]
    public async Task SearchBucketsAsyncValidatesRequestAndCapsLimit()
    {
        var repository = new RecordingRepository();
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now)));

        var result = await service.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Purpose = "", Limit = 500 });
        var valid = await service.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Limit = 500 });

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
        var service = new AuthenticationRateLimitAdministrationService(new RecordingRepository());

        var negativeOffset = await service.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Offset = -1 });
        var zeroLimit = await service.SearchBucketsAsync(new SearchAuthenticationRateLimitBucketsRequest { Limit = 0 });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(negativeOffset.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(zeroLimit.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task LookupAndResetValidateRequests()
    {
        var service = new AuthenticationRateLimitAdministrationService(new RecordingRepository());

        var invalidLookup = await service.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest("", "login"));
        var invalidReset = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "", new AuditContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(invalidLookup.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(invalidReset.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetBucketAsyncReturnsNotFoundForMissingBucket()
    {
        var service = new AuthenticationRateLimitAdministrationService(
            new RecordingRepository(),
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now)));

        var result = await service.GetBucketAsync(new AuthenticationRateLimitBucketLookupRequest("bucket", "login"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.RateLimitBucketNotFound));
        }
    }

    [Test]
    public async Task ResetBucketAsyncAuditsSuccessfulReset()
    {
        var repository = new RecordingRepository { ResetResult = true };
        var sink = new CapturingSecurityEventSink();
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now), sink));
        var actorUserId = Guid.NewGuid();
        var audit = new AuditContext(actorUserId, "127.0.0.1", "tests", "correlation");

        var reset = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("opaque-id", "login", audit));

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
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(
                new FakeTimeProvider(Now),
                new CapturingSecurityEventSink(),
                transactionProvider));

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "login", new AuditContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(transactionProvider.Transaction.BeginCount, Is.EqualTo(1));
            Assert.That(transactionProvider.Transaction.CommitCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ResetBucketAsyncShouldAllowNonAtomicRepositoryWhenPersistentAuditIsNotConfigured()
    {
        var repository = new NonAtomicRecordingRepository { ResetResult = true };
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now), new CapturingSecurityEventSink()));

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "login", new AuditContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(repository.ResetCalls, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ResetBucketAsyncShouldAllowNonAtomicRepositoryWhenDependenciesAreNotConfigured()
    {
        var repository = new NonAtomicRecordingRepository { ResetResult = true };
        var service = new AuthenticationRateLimitAdministrationService(repository);

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "login", new AuditContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(repository.ResetCalls, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ResetBucketAsyncShouldAllowAtomicRepositoryWhenPersistentAuditIsConfigured()
    {
        var repository = new RecordingRepository { ResetResult = true };
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(
                new FakeTimeProvider(Now),
                new CapturingSecurityEventSink(),
                PersistentAuditConfigured: true));

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "login", new AuditContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(repository.ResetCalls, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task ResetBucketAsyncShouldFailClosedForNonAtomicRepositoryWhenPersistentAuditIsConfigured()
    {
        var repository = new NonAtomicRecordingRepository { ResetResult = true };
        var sink = new CapturingSecurityEventSink();
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(
                new FakeTimeProvider(Now),
                sink,
                PersistentAuditConfigured: true));

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "login", new AuditContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Failed));
            Assert.That(repository.ResetCalls, Is.Zero);
            Assert.That(sink.Events, Has.Count.EqualTo(1));
            Assert.That(sink.Events[0].Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
        }
    }

    [Test]
    public async Task ResetBucketAsyncAuditsMissingBucket()
    {
        var repository = new RecordingRepository { ResetResult = false };
        var sink = new CapturingSecurityEventSink();
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now), sink));
        var audit = new AuditContext(Guid.NewGuid(), "127.0.0.1", "tests", "correlation");

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("missing", "login", audit));

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
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now), sink));

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "login", new AuditContext(Guid.NewGuid())));

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
        var service = new AuthenticationRateLimitAdministrationService(
            new RecordingRepository(),
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now), sink));

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "", new AuditContext(Guid.NewGuid())));

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
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now), sink));
        var audit = new AuditContext(Guid.NewGuid(), "127.0.0.1", "tests", "correlation");

        var exception = Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("opaque-id", "login", audit)));

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
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now), sink));

        var exception = Assert.ThrowsAsync<OperationCanceledException>(
            async () => await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("missing", "login", new AuditContext(Guid.NewGuid()))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception!.Message, Is.EqualTo("sink canceled"));
            AssertSafeResetProperties(sink.Events.Single(), "missing", "login", AuthenticationRateLimitBucketResetStatus.NotFound);
        }
    }

    [Test]
    public async Task ResetBucketAsyncSucceedsWithoutAuditSink()
    {
        var repository = new RecordingRepository { ResetResult = true };
        var service = new AuthenticationRateLimitAdministrationService(repository, new AuthenticationRateLimitAdministrationServiceDependencies());

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "login", new AuditContext(Guid.NewGuid())));

        Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
    }

    [Test]
    public void ConstructorValidatesRepository()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationRateLimitAdministrationService(null!));
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

    private class RecordingRepository : IAuthenticationRateLimitAdministrationRepository
    {
        public SearchAuthenticationRateLimitBucketsRequest? LastSearchRequest { get; private set; }

        public bool ResetResult { get; set; }

        public bool ThrowOnReset { get; set; }

        public int ResetCalls { get; private set; }

        public Task<IReadOnlyList<AuthenticationRateLimitBucketSummary>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            IReadOnlyList<AuthenticationRateLimitBucketSummary> result = [];
            return Task.FromResult(result);
        }

        public Task<AuthenticationRateLimitBucketSummary?> GetBucketAsync(AuthenticationRateLimitBucketLookupRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<AuthenticationRateLimitBucketSummary?>(null);
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

    private sealed class NonAtomicRecordingRepository : RecordingRepository, INonAtomicAuthenticationRateLimitAdministrationRepository;

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
