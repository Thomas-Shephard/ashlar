using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Models.Sessions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Testing;
using Moq;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.ProviderContracts.DependencyInjection;

namespace Ashlar.Redis.Tests.RateLimiting;

internal sealed class RedisAuthenticationRateLimitAdministrationContractTests : AuthenticationRateLimitAdministrationContractTests
{
    private readonly RedisTestHost _redis = new();
    private FakeTimeProvider _timeProvider = null!;

    protected override DateTimeOffset Now
    {
        get
        {
            var time = (RedisResult[])_redis.Connection.GetDatabase().Execute("TIME")!;
            return DateTimeOffset.FromUnixTimeMilliseconds((long)time[0] * 1000 + (long)time[1] / 1000);
        }
    }

    protected override bool SupportsReset => false;

    [OneTimeTearDown]
    public async Task DisposeRedisHostAsync()
    {
        await _redis.OneTimeTearDown();
    }

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        await _redis.InitializeAsync();

        _timeProvider = new FakeTimeProvider(Now);
        var services = new ServiceCollection();
        AuthenticationSession? storedSession = null;
        IUser? storedUser = null;
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(repository => repository.CreateSessionAsync(It.IsAny<AuthenticationSession>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationSession, CancellationToken>((session, _) => storedSession = session)
            .Returns(Task.CompletedTask);
        sessions.Setup(repository => repository.GetSessionAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid id, CancellationToken _) => storedSession?.Id == id ? storedSession : null);
        sessions.Setup(repository => repository.GetSessionByTokenHashAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string hash, CancellationToken _) => storedSession?.TokenHash == hash ? storedSession : null);
        sessions.Setup(repository => repository.UpdateSessionLastSeenAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        var users = new Mock<IUserRepository>();
        users.Setup(repository => repository.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()))
            .Callback<IUser, CancellationToken>((user, _) => storedUser = user)
            .Returns(Task.CompletedTask);
        users.Setup(repository => repository.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid id, CancellationToken _) => storedUser?.Id == id ? storedUser : null);
        services.AddAshlarIdentity();
        services.AddScoped(_ => sessions.Object);
        services.AddAshlarProviderScoped<IAuthenticationSessionRepository>(_ => sessions.Object);
        services.AddScoped(_ => users.Object);
        services.AddAshlarProviderScoped<IUserRepository>(_ => users.Object);
        services.AddScoped<IAccountSecurityOperationAuthorizer, AllowAccountSecurityOperationAuthorizer>();
        services.AddAshlarProviderScoped<IPersistentSecurityEventSink>(_ => new NoOpAuditSink());
        services.AddAshlarDurableTransactionProvider<TestDurableTransactionProvider>("Redis contract");
        services.AddAshlarDurableTransactionParticipant<IAuthenticationSessionRepository>();
        services.AddAshlarDurableTransactionParticipant<IUserRepository>();
        services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
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
        Thread.Sleep(duration);
        _timeProvider.Advance(duration);
    }

    protected override TimeSpan TimeTravelDuration(TimeSpan duration) => duration / 240;

    protected override TimeSpan TimeTravelTolerance => TimeSpan.FromSeconds(1);

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

    private sealed class TestDurableTransactionProvider : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IAshlarTransaction>(new TestTransaction());
    }

    private sealed class TestTransaction : IAshlarTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task RollbackAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public void OnCommitted(Func<CancellationToken, Task> action) => ArgumentNullException.ThrowIfNull(action);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
