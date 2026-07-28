using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Ashlar.Testing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Postgres.Tests.RateLimiting;

internal sealed class PostgresAuthenticationRateLimitAdministrationContractTests : AuthenticationRateLimitAdministrationContractTests
{
    private static readonly DateTimeOffset Start = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private PostgresContractDatabaseLease? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override DateTimeOffset Now => _timeProvider.GetUtcNow();

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(Start);
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(services =>
        {
            services.AddAshlarIdentity();
            services.AddAshlarPostgresRateLimiting();
            services.AddScoped<IAccountSecurityOperationAuthorizer, AllowAccountSecurityOperationAuthorizer>();
            services.AddSingleton<TimeProvider>(_timeProvider);
            services.ReplaceAshlarProviderScoped<IPersistentSecurityEventSink>(provider =>
                new FailingResetSecurityEventSink(new PostgresSecurityEventSink(
                    provider.GetRequiredService<IPostgresConnectionProvider>())));
            services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        });
        return _database.ServiceProvider;
    }

    protected override async Task CleanupInitializedServiceProviderAsync()
    {
        if (_database != null)
        {
            await _database.DropDatabaseAsync();
            _database = null;
        }
    }

    protected override void AdvanceTime(TimeSpan duration)
    {
        _timeProvider.Advance(duration);
    }

    [Test]
    public void AdministrationRepositoryConstructorValidatesConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAuthenticationRateLimitAdministrationRepository(null!));
    }

    [Test]
    public async Task ResetRollsBackWhenDurableAuditFailsAfterDelete()
    {
        await using var scope = CreateAsyncScope();
        var services = scope.ServiceProvider;
        var actor = await CreateActorAsync(services, IAccountSecurityAdministrationService.ProofPurpose);
        await services.GetRequiredService<IAuthenticationRateLimiter>().CheckAsync(
            new RateLimitAttempt { Purpose = "audit-rollback", Key = "203.0.113.10" },
            new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(5) });
        var repository = services.GetRequiredService<IAuthenticationRateLimitAdministrationRepository>();
        var bucket = (await repository.SearchBucketsAsync(
            new SearchAuthenticationRateLimitBucketsRequest { Purpose = "audit-rollback", Limit = 10 }, Now)).Single();

        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await services.GetRequiredService<IAuthenticationRateLimitAdministrationService>().ResetBucketAsync(
                actor,
                OperationalAdministrationScope.Global,
                new ResetAuthenticationRateLimitBucketRequest(
                    bucket.BucketId,
                    bucket.Purpose,
                    actor.Audit with { CorrelationId = FailingResetSecurityEventSink.CorrelationId })));

        Assert.That(await repository.GetBucketAsync(
            new AuthenticationRateLimitBucketLookupRequest(bucket.BucketId, bucket.Purpose), Now), Is.Not.Null);
    }

    private sealed class FailingResetSecurityEventSink(IPersistentSecurityEventSink inner) : IPersistentSecurityEventSink
    {
        internal const string CorrelationId = "fail-rate-limit-reset-audit";

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) =>
            securityEvent.CorrelationId == CorrelationId
                && securityEvent.Properties?.GetValueOrDefault("reset_status") == AuthenticationRateLimitBucketResetStatus.Reset.ToString()
                ? Task.FromException(new InvalidOperationException("required audit failed"))
                : inner.RecordAsync(securityEvent, cancellationToken);
    }
}
