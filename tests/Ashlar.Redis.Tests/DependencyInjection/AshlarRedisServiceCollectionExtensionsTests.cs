using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Operational.Diagnostics;
using Ashlar.Security.Encryption;
using Ashlar.Testing.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.DependencyInjection;

internal sealed class AshlarRedisServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarRedisRateLimitingRegistersRedisServices()
    {
        var connection = Mock.Of<IConnectionMultiplexer>();
        var services = new ServiceCollection();

        services.AddAshlarRedisRateLimiting(connection, options => options.KeyPrefix = "custom:prefix");
        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<IAuthenticationRateLimiter>(), Is.TypeOf<RedisAuthenticationRateLimiter>());
            Assert.That(provider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>(), Is.TypeOf<RedisAuthenticationRateLimiterDiagnostics>());
            Assert.That(provider.GetRequiredService<IOptions<RedisAuthenticationRateLimiterOptions>>().Value.KeyPrefix, Is.EqualTo("custom:prefix"));
        }
    }

    [Test]
    public void AddAshlarRedisRateLimitingWithoutConfigureRegistersDefaultOptions()
    {
        var connection = Mock.Of<IConnectionMultiplexer>();
        var services = new ServiceCollection();

        services.AddAshlarRedisRateLimiting(connection);
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IOptions<RedisAuthenticationRateLimiterOptions>>().Value.KeyPrefix, Is.EqualTo("ashlar:rate-limits"));
    }

    [Test]
    public void CoreAndRedisRateLimitingCompositionBuildsWithStrictValidation()
    {
        var customRateLimiter = Mock.Of<IAuthenticationRateLimiter>();
        var connection = Mock.Of<IConnectionMultiplexer>();
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<IUserAdministrationRepository>());
        services.AddSingleton(Mock.Of<ICredentialAdministrationRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionAdministrationRepository>());
        services.AddSingleton(Mock.Of<ISecurityEventAdministrationRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddSingleton(customRateLimiter);
        services.AddAshlarIdentity();

        using (var provider = ServiceProviderValidation.BuildValidatedServiceProvider(services, typeof(IAuthenticationRateLimiter)))
        {
            Assert.That(provider.GetRequiredService<IAuthenticationRateLimiter>(), Is.SameAs(customRateLimiter));
        }

        services.AddAshlarRedisRateLimiting(connection);
        using var redisProvider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IAuthenticationRateLimiter),
            typeof(IAuthenticationRateLimiterDiagnostics));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(redisProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.TypeOf<RedisAuthenticationRateLimiter>());
            Assert.That(redisProvider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>(), Is.TypeOf<RedisAuthenticationRateLimiterDiagnostics>());
        }
    }

    [Test]
    public async Task AddAshlarRedisRateLimitingUsesProvidedConnectionWhenAmbientMultiplexerExists()
    {
        var database = new Mock<IDatabase>(MockBehavior.Strict);
        database
            .Setup(redis => redis.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.IsAny<RedisKey[]>(),
                It.IsAny<RedisValue[]>(),
                CommandFlags.None))
            .ReturnsAsync(RedisResult.Create(
            [
                RedisResult.Create(0),
                RedisResult.Create(0),
                RedisResult.Create(-1),
                RedisResult.Create(DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds())
            ]));

        var ambientConnection = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        var explicitConnection = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        explicitConnection
            .Setup(redis => redis.GetDatabase(-1, null))
            .Returns(database.Object);

        var services = new ServiceCollection();
        services.AddSingleton(ambientConnection.Object);
        services.AddAshlarRedisRateLimiting(explicitConnection.Object);
        using var provider = services.BuildServiceProvider();

        var limiter = provider.GetRequiredService<IAuthenticationRateLimiter>();
        var decision = await limiter.CheckAsync(
            new RateLimitAttempt { Key = "explicit" },
            new RateLimitRule { PermitLimit = 1, Window = TimeSpan.FromMinutes(1) });

        Assert.That(decision.IsAllowed, Is.True);
        explicitConnection.Verify(redis => redis.GetDatabase(-1, null), Times.Once);
        ambientConnection.Verify(redis => redis.GetDatabase(It.IsAny<int>(), It.IsAny<object>()), Times.Never);
    }

    [Test]
    public void AddAshlarRedisRateLimitingRejectsNullArguments()
    {
        var services = new ServiceCollection();
        var connection = Mock.Of<IConnectionMultiplexer>();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarRedisServiceCollectionExtensions.AddAshlarRedisRateLimiting(null!, connection));
            Assert.Throws<ArgumentNullException>(() => services.AddAshlarRedisRateLimiting((IConnectionMultiplexer)null!));
            Assert.Throws<ArgumentException>(() => services.AddAshlarRedisRateLimiting(""));
        }
    }

    [Test]
    public void OptionsValidationRejectsUnsafePrefixesAndNegativeSkew()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "has spaces" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { Database = -1 }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { ExpirationSkew = TimeSpan.FromMilliseconds(-1) }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "ashlar:test" }), Is.True);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { Database = 0 }), Is.True);
        }
    }
}
