using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Providers.Local;
using Ashlar.Messaging;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Operational;
using Ashlar.Operational.Configuration;
using Ashlar.Operational.Diagnostics;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Sqlite.Schema;
using Ashlar.Testing.DependencyInjection;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Sqlite.Tests.DependencyInjection;

internal sealed class AshlarSqliteServiceCollectionExtensionsTests : SqliteTestBase
{
    [Test]
    public async Task AddAshlarSqliteRegistersMinimalPersistenceServices()
    {
        var services = new ServiceCollection();

        services.AddAshlarSqlite(GetConnectionString());

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>(), Is.TypeOf<SqliteTransactionManager>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ISqliteConnectionProvider>(), Is.TypeOf<SqliteTransactionManager>());
            Assert.That(scope.ServiceProvider.GetRequiredService<SqliteSchemaManager>(), Is.Not.Null);
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarSchemaDiagnostics>(), Is.TypeOf<SqliteSchemaDiagnostics>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IUserRepository>(), Is.TypeOf<SqliteUserRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ICredentialRepository>(), Is.TypeOf<SqliteCredentialRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IUserAdministrationRepository>(), Is.TypeOf<SqliteUserAdministrationRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ICredentialAdministrationRepository>(), Is.TypeOf<SqliteCredentialAdministrationRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityEventAdministrationRepository>(), Is.TypeOf<SqliteSecurityEventAdministrationRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationSessionAdministrationRepository>(), Is.TypeOf<SqliteAuthenticationSessionAdministrationRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IBootstrapStateRepository>(), Is.TypeOf<SqliteBootstrapStateRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationSessionRepository>(), Is.TypeOf<SqliteAuthenticationSessionRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationHandshakeRepository>(), Is.TypeOf<SqliteAuthenticationHandshakeRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IInvitationRepository>(), Is.TypeOf<SqliteInvitationRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IPasskeyChallengeRepository>(), Is.TypeOf<SqlitePasskeyChallengeRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthorizationGrantRepository>(), Is.TypeOf<SqliteAuthorizationGrantRepository>());
            Assert.That(provider.GetRequiredService<TimeProvider>(), Is.EqualTo(TimeProvider.System));
        }
    }

    [Test]
    public void AddAshlarSqliteShouldReplaceAmbientConnectionFactory()
    {
        var services = new ServiceCollection();
        var ambient = new SqliteConnectionFactory("Data Source=:memory:");
        services.AddSingleton(ambient);

        services.AddAshlarSqlite(GetConnectionString());
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<SqliteConnectionFactory>(), Is.Not.SameAs(ambient));
    }

    [Test]
    public async Task AddAshlarSqliteCompositionBuildsWithStrictValidation()
    {
        var secretProtector = Mock.Of<ISecretProtector>();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(secretProtector);
        services.AddAshlarIdentity();
        services.AddPasswordHasher<PasswordHasherV1>();
        services.AddAuthenticationProvider<LocalPasswordProvider>();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarAuthorization();
        services.AddAshlarSqliteAuditSink();
        services.AddAshlarSqliteRateLimiting();
        services.AddAshlarSqliteCleanup();
        services.AddAshlarSqliteEmailOutboxDispatcher<TestEmailTransport>();
        services.AddAshlarSqliteSecurityEventWebhookDispatcher(configureWebhooks: options =>
        {
            options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
            {
                Name = "test",
                Uri = new Uri("https://webhooks.example.test/ashlar"),
                SharedSecret = "test-secret"
            });
        });

        await using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IIdentityService),
            typeof(IAuthorizationGrantService),
            typeof(IAshlarCleanupService),
            typeof(IEmailOutboxDispatcher),
            typeof(SqliteSecurityEventWebhookOutboxDispatcher),
            typeof(IAuthenticationRateLimiter),
            typeof(IAshlarSchemaDiagnostics));
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecretProtector>(), Is.SameAs(secretProtector));
            Assert.That(scope.ServiceProvider.GetRequiredService<IEmailSender>(), Is.TypeOf<SqliteEmailOutboxSender>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.TypeOf<SqliteAuthenticationRateLimiter>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>(), Is.TypeOf<SqliteTransactionManager>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IPersistentSecurityEventSink>(), Is.TypeOf<SqliteSecurityEventSink>());
            Assert.That(provider.GetServices<IHostedService>(), Is.Empty);
        }
    }

    [Test]
    public async Task AddAshlarSqliteDoesNotRegisterOptionalOperationalLayers()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();
        services.AddAshlarSqlite(GetConnectionString());

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.Not.TypeOf<SqliteAuthenticationRateLimiter>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>(), Is.Not.TypeOf<SqliteAuthenticationRateLimiterDiagnostics>());
            Assert.That(scope.ServiceProvider.GetService<IAshlarCleanupService>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAshlarCleanupDiagnostics>(), Is.Null);
            Assert.That(provider.GetRequiredService<ISecurityEventSink>(), Is.Not.TypeOf<SqliteSecurityEventSink>());
            Assert.That(provider.GetService<IUserSecurityEventSummaryRepository>(), Is.Null);
            Assert.That(provider.GetServices<IHostedService>(), Is.Empty);
        }
    }

    [Test]
    public async Task AddAshlarSqliteSuppressesNullTransactionConfigurationWarning()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();
        services.AddAshlarSqlite(GetConnectionString());

        await using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain("ASHLAR-CONFIG-NULL-TRANSACTION-PROVIDER"));
    }

    [Test]
    public async Task AddAshlarSqliteDoesNotSuppressAuditOrRateLimiterConfigurationWarnings()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();
        services.AddAshlarSqlite(GetConnectionString());

        await using var provider = services.BuildServiceProvider();

        var issueCodes = (await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync()).Issues.Select(issue => issue.Code);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(issueCodes, Does.Contain(AshlarConfigurationIssueCodes.NullSecurityEventSink));
            Assert.That(issueCodes, Does.Contain(AshlarConfigurationIssueCodes.InMemoryAuthenticationRateLimiter));
        }
    }

    [Test]
    public async Task AddAshlarSqliteAuditSinkClearsNullSecurityEventSinkWarning()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteAuditSink();

        await using var provider = services.BuildServiceProvider();

        var issueCodes = (await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync()).Issues.Select(issue => issue.Code);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(provider.GetRequiredService<IPersistentSecurityEventSink>(), Is.TypeOf<SqliteSecurityEventSink>());
            Assert.That(provider.GetRequiredService<IUserSecurityEventSummaryRepository>(), Is.SameAs(provider.GetRequiredService<IPersistentSecurityEventSink>()));
            Assert.That(issueCodes, Does.Not.Contain(AshlarConfigurationIssueCodes.NullSecurityEventSink));
        }
    }

    [Test]
    public async Task AddAshlarSqliteRateLimitingClearsInMemoryRateLimiterWarning()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteRateLimiting();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        var issueCodes = (await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync()).Issues.Select(issue => issue.Code);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.TypeOf<SqliteAuthenticationRateLimiter>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>(), Is.TypeOf<SqliteAuthenticationRateLimiterDiagnostics>());
            Assert.That(issueCodes, Does.Not.Contain(AshlarConfigurationIssueCodes.InMemoryAuthenticationRateLimiter));
        }
    }

    [Test]
    public async Task AddAshlarSqliteCleanupRegistersCleanupDiagnostics()
    {
        var services = new ServiceCollection();

        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteCleanup(options =>
        {
            options.CleanupInterval = TimeSpan.FromMinutes(30);
            options.BatchSize = 42;
            options.MaxBatchesPerRun = 2;
            options.RemoveAuditEventsAfter = TimeSpan.FromDays(1);
            options.RemoveFailedEmailsAfter = null;
        });

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var result = await scope.ServiceProvider.GetRequiredService<IAshlarCleanupDiagnostics>().CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarCleanupService>(), Is.TypeOf<SqliteAshlarCleanupService>());
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("Sqlite"));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.OptionsValid, Is.True);
            Assert.That(result.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(30)));
            Assert.That(result.BatchSize, Is.EqualTo(42));
            Assert.That(result.MaxBatchesPerRun, Is.EqualTo(2));
            Assert.That(result.EnabledCategoryCount, Is.EqualTo(22));
            Assert.That(result.DisabledCategoryCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void AddAshlarSqliteCleanupHostedServiceRegistersHostedService()
    {
        var services = new ServiceCollection();

        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteCleanupHostedService();
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetServices<IHostedService>().Single(), Is.TypeOf<SqliteAshlarCleanupHostedService>());
    }

    [Test]
    public void AddAshlarSqliteHostedServiceMethodsRegisterOnlyExplicitHostedServices()
    {
        var services = new ServiceCollection();

        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteCleanupHostedService();
        services.AddAshlarSqliteEmailOutboxHostedService<TestEmailTransport>();
        services.AddAshlarSqliteSecurityEventWebhookHostedService();

        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(services);

        Assert.That(provider.GetServices<IHostedService>(), Has.Exactly(3).Items);
    }

    [Test]
    public void SqliteAshlarCleanupDiagnosticsRejectsNullArguments()
    {
        var options = Options.Create(new AshlarCleanupOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteAshlarCleanupDiagnostics(null!, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteAshlarCleanupDiagnostics(options, null!));
        }
    }

    [Test]
    public void AddAshlarSqliteRejectsInvalidArguments()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentNullException>(() => AshlarSqliteServiceCollectionExtensions.AddAshlarSqlite(null!, GetConnectionString()));
        Assert.Throws<ArgumentException>(() => services.AddAshlarSqlite(string.Empty));
        Assert.Throws<ArgumentNullException>(() => AshlarSqliteServiceCollectionExtensions.AddAshlarSqliteAuditSink(null!));
        Assert.Throws<ArgumentNullException>(() => AshlarSqliteServiceCollectionExtensions.AddAshlarSqliteRateLimiting(null!));
        Assert.Throws<ArgumentNullException>(() => AshlarSqliteServiceCollectionExtensions.AddAshlarSqliteCleanup(null!));
        Assert.Throws<ArgumentNullException>(() => AshlarSqliteServiceCollectionExtensions.AddAshlarSqliteCleanupHostedService(null!));
        Assert.Throws<ArgumentException>(() => _ = new SqliteConnectionFactory(string.Empty));
    }

    [Test]
    public void InitializeAshlarSqliteSchemaAsyncRejectsNullProvider()
    {
        Assert.ThrowsAsync<ArgumentNullException>(async () => await AshlarSqliteServiceCollectionExtensions.InitializeAshlarSqliteSchemaAsync(null!));
    }

    [Test]
    public async Task RepositoryConstructorsUseSystemTimeProviderByDefault()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());

        await using var provider = services.BuildServiceProvider();
        var connectionProvider = provider.GetRequiredService<ISqliteConnectionProvider>();

        using (Assert.EnterMultipleScope())
        {
            Assert.DoesNotThrow(() => _ = new SqliteUserRepository(connectionProvider));
            Assert.DoesNotThrow(() => _ = new SqliteCredentialRepository(connectionProvider));
            Assert.DoesNotThrow(() => _ = new SqliteInvitationRepository(connectionProvider));
            Assert.DoesNotThrow(() => _ = new SqliteAuthenticationHandshakeRepository(connectionProvider));
        }
    }

    private sealed class TestEmailTransport : IEmailTransport
    {
        public Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
