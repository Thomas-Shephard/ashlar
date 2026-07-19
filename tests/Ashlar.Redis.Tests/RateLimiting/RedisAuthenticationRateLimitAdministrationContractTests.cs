using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Models.Sessions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.ProviderContracts.DependencyInjection;
using Ashlar.Testing;
using Moq;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimitAdministrationContractTests : AuthenticationRateLimitAdministrationContractTests
{
    private static readonly DateTimeOffset Start = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly RedisTestHost _redis = new();
    private FakeTimeProvider _timeProvider = null!;

    protected override DateTimeOffset Now => _timeProvider.GetUtcNow();

    protected override bool SupportsReset => false;

    [OneTimeTearDown]
    public async Task DisposeRedisHostAsync()
    {
        await _redis.OneTimeTearDown();
    }

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        await _redis.InitializeAsync();

        _timeProvider = new FakeTimeProvider(Start);
        var services = new ServiceCollection();
        AuthenticationSession? storedSession = null;
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(repository => repository.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);
        sessions.Setup(repository => repository.GetSessionAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid id, CancellationToken _) => storedSession?.Id == id ? storedSession : null);
        services.AddAshlarIdentity();
        services.AddScoped(_ => sessions.Object);
        services.AddAshlarProviderScoped<IAuthenticationSessionRepository>(_ => sessions.Object);
        services.AddScoped<IAccountSecurityOperationAuthorizer, AllowAccountSecurityOperationAuthorizer>();
        services.AddAshlarProviderScoped<IPersistentSecurityEventSink>(_ => new NoOpAuditSink());
        services.AddAshlarRedisRateLimiting(_redis.Connection, options => options.KeyPrefix = $"ashlar:test:{Guid.NewGuid():N}");
        services.AddSingleton<TimeProvider>(_timeProvider);
        var provider = services.BuildServiceProvider();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<IAuthenticationRateLimitAdministrationReaderRepository>(), Is.Null);
            Assert.That(provider.GetService<IAuthenticationRateLimitAdministrationRepository>(), Is.Null);
        }
        return provider;
    }

    protected override void AdvanceTime(TimeSpan duration)
    {
        _timeProvider.Advance(duration);
    }

    private sealed class RedisTestHost : RedisTestBase
    {
        public IConnectionMultiplexer Connection => GetConnection();

        public async Task InitializeAsync()
        {
            await OneTimeSetUp();
        }
    }

    private sealed class NoOpAuditSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
