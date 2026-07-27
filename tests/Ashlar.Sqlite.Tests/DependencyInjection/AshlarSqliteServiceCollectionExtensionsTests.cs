using Ashlar.Testing;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Providers.Local;
using Ashlar.Messaging;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Operational;
using Ashlar.Operational.Configuration;
using Ashlar.Operational.Diagnostics;
using Ashlar.Passkeys;
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
    private const string ValidSecret = "0123456789abcdef0123456789abcdef";

    [TestCase(false)]
    [TestCase(true)]
    public void AddAshlarSqliteRejectsConflictingDurableProviderFamily(bool sqliteFirst)
    {
        var services = new ServiceCollection();
        if (sqliteFirst) services.AddAshlarSqlite(GetConnectionString());
        else services.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("PostgreSQL");

        Assert.Throws<InvalidOperationException>(() =>
        {
            if (sqliteFirst) services.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("PostgreSQL");
            else services.AddAshlarSqlite(GetConnectionString());
        });
    }

    [Test]
    public void AddAshlarSqliteAllowsRepeatedRegistration()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());

        Assert.DoesNotThrow(() => services.AddAshlarSqlite(GetConnectionString()));
    }

    [Test]
    public void SqliteOutboxesRejectConflictingDurableProviderFamily()
    {
        var services = new ServiceCollection();
        services.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("PostgreSQL");

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<InvalidOperationException>(() => services.AddAshlarSqliteEmailOutboxSender());
            Assert.Throws<InvalidOperationException>(() => services.AddAshlarSqliteSecurityEventWebhookOutbox());
        }
    }

    [Test]
    public void RejectedSqliteCompositeRegistrationsLeaveNoResidue()
    {
        var rateLimiting = new ServiceCollection();
        rateLimiting.AddAshlarAuthenticationRateLimitProviderMarker("Redis");
        Assert.Throws<InvalidOperationException>(() => rateLimiting.AddAshlarSqliteRateLimiting());
        Assert.DoesNotThrow(() => rateLimiting.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("PostgreSQL"));

        var webhooks = new ServiceCollection();
        webhooks.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("PostgreSQL");
        var count = webhooks.Count;
        Assert.Throws<InvalidOperationException>(() => webhooks.AddAshlarSqliteSecurityEventWebhookDispatcher());
        Assert.That(webhooks, Has.Count.EqualTo(count));
    }

    [Test]
    public void AddAshlarSqliteRegistersMinimalPersistenceServices()
    {
        var services = new ServiceCollection();

        services.AddAshlarSqlite(GetConnectionString());

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(typeof(ISqliteConnectionProvider).IsNotPublic, Is.True);
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.TypeOf<AshlarDurableTransactionProvider>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ISqliteConnectionProvider>(), Is.TypeOf<SqliteTransactionManagerOwner>());
            Assert.That(scope.ServiceProvider.GetService<SqliteTransactionManager>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetRequiredService<SqliteSchemaManager>(), Is.Not.Null);
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarSchemaDiagnostics>(), Is.TypeOf<SqliteSchemaDiagnostics>());
            Assert.That(scope.ServiceProvider.GetService<IUserRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<ICredentialRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAccountLockoutRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IUserAdministrationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<ICredentialAdministrationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<ISecurityEventAdministrationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAuthenticationSessionAdministrationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IBootstrapStateRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAuthenticationSessionRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAuthenticationHandshakeRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IInvitationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IRememberedMfaDeviceRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IPasskeyChallengeRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAuthorizationGrantRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAuthorizationGrantAdministrationRepository>(), Is.Null);
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
        services.AddPermissiveAccountSecurityGuard();
        services.AddPasswordHasher<PasswordHasherV1>();
        services.AddAuthenticationProvider<LocalPasswordProvider>();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddSqliteProviderContractTestServices();
        services.AddAshlarAuthorization();
        services.AddAshlarNoMfaPolicy();
        services.AddAshlarPasskeys(options =>
        {
            options.RelyingPartyId = "localhost";
            options.Origin = "https://localhost";
        });
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
                SharedSecret = ValidSecret
            });
        });
        AddWebhookOperationalSecurity(services);

        await using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IIdentityService),
            typeof(IPasskeyService),
            typeof(IAuthorizationGrantService),
            typeof(IAshlarCleanupService),
            typeof(IEmailOutboxDispatcher),
            typeof(SqliteSecurityEventWebhookOutboxDispatcher),
            typeof(IAuthenticationRateLimiter),
            typeof(IAshlarSchemaDiagnostics));
        await using var scope = provider.CreateAsyncScope();
        scope.ServiceProvider.AssertSqliteProviderContractsRegistered();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecretProtector>(), Is.SameAs(secretProtector));
            Assert.That(scope.ServiceProvider.GetRequiredService<IEmailSender>(), Is.TypeOf<SqliteEmailOutboxSender>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.TypeOf<SqliteAuthenticationRateLimiter>());
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.TypeOf<AshlarDurableTransactionProvider>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IPersistentSecurityEventSink>(), Is.TypeOf<SqliteSecurityEventSink>());
            Assert.That(provider.GetServices<IHostedService>(), Is.Empty);
        }
    }

    [Test]
    public async Task AddAshlarSqliteRateLimitingIgnoresOrdinaryTransactionReplacement()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddAshlarSqliteRateLimiting();
        services.AddScoped(_ => Mock.Of<IAshlarTransactionProvider>());

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var limiter = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>();
        var transactions = scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>();

        Assert.That(typeof(SqliteAuthenticationRateLimiter)
            .GetField("_transactionProvider", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(limiter), Is.SameAs(transactions));
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
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarOperationsSummaryService>(), Is.TypeOf<AshlarOperationsSummaryService>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityEventSink>(), Is.Not.TypeOf<SqliteSecurityEventSink>());
            Assert.That(scope.ServiceProvider.GetService<IUserSecurityEventSummaryRepository>(), Is.Null);
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
        await using var scope = provider.CreateAsyncScope();

        var issueCodes = (await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync()).Issues.Select(issue => issue.Code);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(scope.ServiceProvider.GetService<IPersistentSecurityEventSink>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetRequiredService<IUserSecurityEventSummaryRepository>(), Is.TypeOf<SqliteUserSecurityEventSummaryRepository>());
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
            Assert.That(result.ProviderName, Is.EqualTo("SQLite"));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.OptionsValid, Is.True);
            Assert.That(result.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(30)));
            Assert.That(result.BatchSize, Is.EqualTo(42));
            Assert.That(result.MaxBatchesPerRun, Is.EqualTo(2));
            Assert.That(result.EnabledCategoryCount, Is.EqualTo(26));
            Assert.That(result.DisabledCategoryCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void AddAshlarSqliteCleanupValidatesOptionsOnStart()
    {
        var services = new ServiceCollection();

        services.AddAshlarSqliteCleanup(options => options.BatchSize = 0);

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(AshlarCleanupOptions)));
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
        AddWebhookOperationalSecurity(services);

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

    private static void AddWebhookOperationalSecurity(IServiceCollection services)
    {
        var security = new AccountSecurityActorTestContext(
            DateTimeOffset.UtcNow,
            IAccountSecurityAdministrationService.ProofPurpose);
        services.AddSingleton<IAuthenticationSessionRepository>(security.Sessions);
        services.AddSingleton<IAccountSecurityOperationAuthorizer>(security.Authorizer);
        if (!services.Any(service => service.ServiceType == typeof(IPersistentSecurityEventSink)))
            services.AddSingleton<IPersistentSecurityEventSink>(security.AuditSink);
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
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteAuthorizationGrantAdministrationRepository(null!));
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
        await using var scope = provider.CreateAsyncScope();
        var connectionProvider = scope.ServiceProvider.GetRequiredService<ISqliteConnectionProvider>();

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
