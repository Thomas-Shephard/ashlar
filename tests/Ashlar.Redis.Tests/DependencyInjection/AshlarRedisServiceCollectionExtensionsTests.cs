using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.ProviderContracts.DependencyInjection;
using Ashlar.Testing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Operational.Configuration;
using Ashlar.Operational.Diagnostics;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Testing.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using StackExchange.Redis;

namespace Ashlar.Redis.Tests.DependencyInjection;

internal sealed class AshlarRedisServiceCollectionExtensionsTests
{
    [TestCase(false)]
    [TestCase(true)]
    public void ConflictingRateLimitProviderMarkerIsRejectedInEitherOrder(bool redisFirst)
    {
        var services = new ServiceCollection();
        var connection = Mock.Of<IConnectionMultiplexer>();

        if (redisFirst)
        {
            services.AddAshlarRedisRateLimiting(connection, options => options.KeyPrefix = "test");
        }
        else
        {
            services.AddAshlarAuthenticationRateLimitProviderMarker("PostgreSQL");
        }

        var exception = Assert.Throws<InvalidOperationException>(() =>
        {
            if (redisFirst)
            {
                services.AddAshlarAuthenticationRateLimitProviderMarker("PostgreSQL");
            }
            else
            {
                services.AddAshlarRedisRateLimiting(connection, options => options.KeyPrefix = "test");
            }
        });

        Assert.That(exception!.Message, Does.StartWith("Multiple authentication rate-limit providers are not supported."));
    }

    [Test]
    public void AddAshlarRedisRateLimitingRegistersRedisServices()
    {
        var connection = Mock.Of<IConnectionMultiplexer>();
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        services.AddSingleton<IAccountSecurityOperationAuthorizer, AllowAccountSecurityOperationAuthorizer>();
        services.AddAshlarProviderScoped<IAuthenticationSessionRepository>(_ => Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarProviderScoped<IPersistentSecurityEventSink>(_ => Mock.Of<IPersistentSecurityEventSink>());

        services.AddAshlarRedisRateLimiting(connection, options => options.KeyPrefix = "custom:prefix");
        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<IAuthenticationRateLimiter>(), Is.TypeOf<RedisAuthenticationRateLimiter>());
            Assert.That(provider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>(), Is.TypeOf<RedisAuthenticationRateLimiterDiagnostics>());
            Assert.That(provider.GetRequiredService<IAuthenticationRateLimitAdministrationReader>(), Is.Not.Null);
            Assert.That(provider.GetService<IAuthenticationRateLimitAdministrationService>(), Is.Null);
            Assert.That(provider.GetRequiredService<IOptions<RedisAuthenticationRateLimiterOptions>>().Value.KeyPrefix, Is.EqualTo("custom:prefix"));
            Assert.That(provider.GetService<RedisAuthenticationRateLimitAdministrationRepository>(), Is.Null);
            Assert.That(provider.GetService<IAuthenticationRateLimitAdministrationReaderRepository>(), Is.Null);
            Assert.That(provider.GetService<IAuthenticationRateLimitAdministrationRepository>(), Is.Null);
        }
    }

    [Test]
    public void AddAshlarRedisRateLimitingWithoutConfigureRequiresExplicitKeyPrefixOnStart()
    {
        var connection = Mock.Of<IConnectionMultiplexer>();
        var services = new ServiceCollection();

        services.AddAshlarRedisRateLimiting(connection);
        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(RedisAuthenticationRateLimiterOptions)));
    }

    [Test]
    public async Task AddAshlarRedisRateLimitingClearsInMemoryRateLimiterWarning()
    {
        var connection = Mock.Of<IConnectionMultiplexer>();
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        services.AddAshlarRedisRateLimiting(connection, options => options.KeyPrefix = "test-app:ashlar:rate-limits");
        using var provider = services.BuildServiceProvider();

        var issueCodes = (await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync()).Issues.Select(issue => issue.Code);

        Assert.That(issueCodes, Does.Not.Contain(AshlarConfigurationIssueCodes.InMemoryAuthenticationRateLimiter));
    }

    [Test]
    public void AddAshlarRedisRateLimitingValidatesOptionsOnStart()
    {
        var connection = Mock.Of<IConnectionMultiplexer>();
        var services = new ServiceCollection();

        services.AddAshlarRedisRateLimiting(connection, options => options.KeyPrefix = "");

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(RedisAuthenticationRateLimiterOptions)));
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
        services.AddPermissiveAccountSecurityGuard();
        services.AddPasswordHasher<PasswordHasherV1>();

        using (var provider = ServiceProviderValidation.BuildValidatedServiceProvider(services, typeof(IAuthenticationRateLimiter)))
        {
            Assert.That(provider.GetRequiredService<IAuthenticationRateLimiter>(), Is.SameAs(customRateLimiter));
        }

        services.AddAshlarRedisRateLimiting(connection, options => options.KeyPrefix = "test-app:ashlar:rate-limits");
        using var redisProvider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IAuthenticationRateLimiter),
            typeof(IAuthenticationRateLimiterDiagnostics),
            typeof(IAshlarOperationsSummaryService));
        using var redisScope = redisProvider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(redisProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.TypeOf<RedisAuthenticationRateLimiter>());
            Assert.That(redisProvider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>(), Is.TypeOf<RedisAuthenticationRateLimiterDiagnostics>());
            Assert.That(redisScope.ServiceProvider.GetRequiredService<IAshlarOperationsSummaryService>(), Is.TypeOf<AshlarOperationsSummaryService>());
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
        services.AddAshlarRedisRateLimiting(explicitConnection.Object, options => options.KeyPrefix = "test-app:ashlar:rate-limits");
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
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "   " }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = ":" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "has spaces" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "has\tspaces" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "has*glob" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "has?glob" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "has[glob]" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "has{brace" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "ashlar:rate-limits" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "ashlar:rate-limits:" }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "ashlar:test", Database = -1 }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "ashlar:test", ExpirationSkew = TimeSpan.FromMilliseconds(-1) }), Is.False);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "APP1:Ashlar.Test" }), Is.True);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "my-app_1.ashlar:test:" }), Is.True);
            Assert.That(RedisAuthenticationRateLimiterOptions.Validate(new RedisAuthenticationRateLimiterOptions { KeyPrefix = "ashlar:test", Database = 0 }), Is.True);
        }
    }
}
