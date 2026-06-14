using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Identity.RateLimiting;

internal sealed class AuthenticationRateLimitAdministrationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

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
    public async Task DetailAndResetValidateRequests()
    {
        var service = new AuthenticationRateLimitAdministrationService(new RecordingRepository());

        var invalidDetail = await service.GetBucketAsync(new AuthenticationRateLimitBucketDetailRequest("", "login"));
        var invalidReset = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "", new AuditContext(Guid.NewGuid())));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(invalidDetail.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(invalidReset.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetBucketAsyncReturnsNotFoundForMissingBucket()
    {
        var service = new AuthenticationRateLimitAdministrationService(
            new RecordingRepository(),
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now)));

        var result = await service.GetBucketAsync(new AuthenticationRateLimitBucketDetailRequest("bucket", "login"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.RateLimitBucketNotFound));
        }
    }

    [Test]
    public async Task ResetBucketAsyncAuditsSuccessfulResetOnly()
    {
        var repository = new RecordingRepository { ResetResult = true };
        var sink = new CapturingSecurityEventSink();
        var service = new AuthenticationRateLimitAdministrationService(
            repository,
            new AuthenticationRateLimitAdministrationServiceDependencies(new FakeTimeProvider(Now), sink));
        var audit = new AuditContext(Guid.NewGuid(), "127.0.0.1", "tests", "correlation");

        var reset = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("opaque-id", "login", audit));
        repository.ResetResult = false;
        var missing = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("missing", "login", audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(reset.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Reset));
            Assert.That(missing.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.NotFound));
            Assert.That(sink.Events, Has.Count.EqualTo(1));
            var securityEvent = sink.Events[0];
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimitBucketReset));
            Assert.That(securityEvent.Properties, Is.Not.Null);
            Assert.That(securityEvent.Properties!["purpose"], Is.EqualTo("login"));
            Assert.That(securityEvent.Properties["bucket_id"], Is.EqualTo("opaque-id"));
            Assert.That(securityEvent.Properties.Values, Has.None.Contains("127.0.0.1"));
            Assert.That(securityEvent.Properties.Values, Has.None.Contains("correlation"));
        }
    }

    [Test]
    public async Task ResetBucketAsyncReturnsFailedWhenRepositoryThrows()
    {
        var repository = new RecordingRepository { ThrowOnReset = true };
        var service = new AuthenticationRateLimitAdministrationService(repository);

        var result = await service.ResetBucketAsync(new ResetAuthenticationRateLimitBucketRequest("bucket", "login", new AuditContext(Guid.NewGuid())));

        Assert.That(result.Value!.Status, Is.EqualTo(AuthenticationRateLimitBucketResetStatus.Failed));
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
            typeof(AuthenticationRateLimitBucketDetail),
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

        public Task<IReadOnlyList<AuthenticationRateLimitBucketSummary>> SearchBucketsAsync(SearchAuthenticationRateLimitBucketsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            LastSearchRequest = request;
            IReadOnlyList<AuthenticationRateLimitBucketSummary> result = [];
            return Task.FromResult(result);
        }

        public Task<AuthenticationRateLimitBucketDetail?> GetBucketAsync(AuthenticationRateLimitBucketDetailRequest request, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<AuthenticationRateLimitBucketDetail?>(null);
        }

        public Task<bool> ResetBucketAsync(ResetAuthenticationRateLimitBucketRequest request, CancellationToken cancellationToken = default)
        {
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
}
