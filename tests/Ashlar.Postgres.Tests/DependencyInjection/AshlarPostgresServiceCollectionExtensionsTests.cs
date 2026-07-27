using System.Diagnostics.CodeAnalysis;
using Ashlar.Operational;
using Ashlar.Operational.Configuration;
using Ashlar.Operational.Diagnostics;
using Ashlar.Postgres.Schema;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Npgsql;

namespace Ashlar.Postgres.Tests.DependencyInjection;

internal sealed class AshlarPostgresServiceCollectionExtensionsTests : PostgresTestBase
{
    [TestCase(false)]
    [TestCase(true)]
    public void AddAshlarPostgresRejectsConflictingDurableProviderFamily(bool postgresFirst)
    {
        var services = new ServiceCollection();
        if (postgresFirst) services.AddAshlarPostgres("Host=localhost;Database=test");
        else services.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("SQLite");

        Assert.Throws<InvalidOperationException>(() =>
        {
            if (postgresFirst) services.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("SQLite");
            else services.AddAshlarPostgres("Host=localhost;Database=test");
        });
    }

    [Test]
    public void AddAshlarPostgresAllowsRepeatedRegistration()
    {
        var services = new ServiceCollection();
        services.AddAshlarPostgres("Host=localhost;Database=test");

        Assert.DoesNotThrow(() => services.AddAshlarPostgres("Host=localhost;Database=test"));
    }

    [Test]
    public void RejectedPostgresRegistrationDoesNotReplaceDataSource()
    {
        var services = new ServiceCollection();
        var ambient = GetDataSource();
        services.AddSingleton(ambient);
        services.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("SQLite");

        Assert.Throws<InvalidOperationException>(() => services.AddAshlarPostgres("Host=localhost;Database=test"));

        Assert.That(services.Single(descriptor => descriptor.ServiceType == typeof(NpgsqlDataSource)).ImplementationInstance, Is.SameAs(ambient));
    }

    [Test]
    public void PostgresOutboxesRejectConflictingDurableProviderFamily()
    {
        var services = new ServiceCollection();
        services.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("SQLite");

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<InvalidOperationException>(() => services.AddAshlarPostgresEmailOutboxSender());
            Assert.Throws<InvalidOperationException>(() => services.AddAshlarPostgresSecurityEventWebhookOutbox());
        }
    }

    [Test]
    public void RejectedPostgresCompositeRegistrationsLeaveNoResidue()
    {
        var rateLimiting = new ServiceCollection();
        rateLimiting.AddAshlarAuthenticationRateLimitProviderMarker("Redis");
        Assert.Throws<InvalidOperationException>(() => rateLimiting.AddAshlarPostgresRateLimiting());
        Assert.DoesNotThrow(() => rateLimiting.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("SQLite"));

        var webhooks = new ServiceCollection();
        webhooks.AddAshlarDurableProviderBundle<IAshlarTransactionProvider>("SQLite");
        var count = webhooks.Count;
        Assert.Throws<InvalidOperationException>(() => webhooks.AddAshlarPostgresSecurityEventWebhookDispatcher());
        Assert.That(webhooks, Has.Count.EqualTo(count));
    }

    [Test]
    public async Task AddAshlarPostgresWithDataSourceShouldRegisterServices()
    {
        var services = new ServiceCollection();
        var dataSource = GetDataSource();

        services.AddAshlarPostgres(dataSource);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<NpgsqlDataSource>(), Is.SameAs(dataSource));
            Assert.That(provider.GetService<TimeProvider>(), Is.Not.Null);
            Assert.That(typeof(IPostgresConnectionProvider).IsNotPublic, Is.True);
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.TypeOf<AshlarDurableTransactionProvider>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>(), Is.TypeOf<PostgresTransactionManagerOwner>());
            Assert.That(scope.ServiceProvider.GetService<IAshlarSchemaDiagnostics>(), Is.TypeOf<PostgresSchemaDiagnostics>());
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IUserRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.ICredentialRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IAccountLockoutRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IUserAdministrationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.ICredentialAdministrationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<ISecurityEventAdministrationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IAuthenticationSessionAdministrationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IBootstrapStateRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IInvitationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IAuthenticationSessionRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IAuthenticationHandshakeRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IRememberedMfaDeviceRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<Ashlar.Identity.Abstractions.Repositories.IPasskeyChallengeRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAuthorizationGrantRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAuthorizationGrantAdministrationRepository>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<SchemaManager>(), Is.Not.Null);
        }
    }

    [Test]
    public async Task AddAshlarPostgresSuppressesNullTransactionConfigurationWarning()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();
        services.AddAshlarPostgres(GetDataSource());

        await using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain("ASHLAR-CONFIG-NULL-TRANSACTION-PROVIDER"));
    }

    [Test]
    public async Task AddAshlarPostgresAuthorizationRegistersTransactionProvider()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresAuthorization(GetDataSource());
        Assert.That(services, Has.None.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(IAuthorizationGrantAdministrationRepository)));
        services.AddPostgresProviderContractTestServices();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.TypeOf<AshlarDurableTransactionProvider>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>(), Is.TypeOf<PostgresTransactionManagerOwner>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthorizationGrantRepository>(), Is.TypeOf<PostgresAuthorizationGrantRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthorizationGrantAdministrationRepository>(), Is.TypeOf<PostgresAuthorizationGrantAdministrationRepository>());
        }
    }

    [Test]
    public async Task AddAshlarPostgresAuthorizationSuppressesNullTransactionConfigurationWarning()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresAuthorization(GetDataSource());

        await using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain("ASHLAR-CONFIG-NULL-TRANSACTION-PROVIDER"));
    }

    [Test]
    public void AddAshlarPostgresNullArgumentsShouldThrow()
    {
        var services = new ServiceCollection();
        var dataSource = GetDataSource();

        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => AshlarPostgresServiceCollectionExtensions.AddAshlarPostgres(null!, "conn"));
            Assert.Throws<ArgumentException>(() => services.AddAshlarPostgres(string.Empty));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => AshlarPostgresServiceCollectionExtensions.AddAshlarPostgres(null!, dataSource));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => services.AddAshlarPostgres((NpgsqlDataSource)null!));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => AshlarPostgresServiceCollectionExtensions.AddAshlarPostgresAuthorization(null!, "conn"));
            Assert.Throws<ArgumentException>(() => services.AddAshlarPostgresAuthorization(string.Empty));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => AshlarPostgresServiceCollectionExtensions.AddAshlarPostgresAuthorization(null!, dataSource));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => services.AddAshlarPostgresAuthorization((NpgsqlDataSource)null!));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresAuthorizationGrantAdministrationRepository(null!));
        }
    }

    [Test]
    public void InitializeAshlarPostgresSchemaAsyncNullProviderShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(async () => await AshlarPostgresServiceCollectionExtensions.InitializeAshlarPostgresSchemaAsync(null!));
    }

    [Test]
    public async Task AddAshlarPostgresCleanupRegistersCleanupService()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgres(GetDataSource());
        services.AddAshlarPostgresCleanup(options => options.BatchSize = 42);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarCleanupService>(), Is.TypeOf<PostgresAshlarCleanupService>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarCleanupDiagnostics>(), Is.TypeOf<PostgresAshlarCleanupDiagnostics>());
            Assert.That(provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AshlarCleanupOptions>>().Value.BatchSize, Is.EqualTo(42));
        }
    }

    [Test]
    public void AddAshlarPostgresCleanupValidatesOptionsOnStart()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresCleanup(options => options.BatchSize = 0);

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(AshlarCleanupOptions)));
    }

    [Test]
    public async Task AddAshlarPostgresCleanupRegistersCleanupDiagnostics()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgres(GetDataSource());
        services.AddAshlarPostgresCleanup(options =>
        {
            options.CleanupInterval = TimeSpan.FromMinutes(30);
            options.BatchSize = 42;
            options.MaxBatchesPerRun = 2;
            options.RemoveAuditEventsAfter = TimeSpan.FromDays(1);
            options.RemoveFailedEmailsAfter = null;
        });
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<IAshlarCleanupDiagnostics>().CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("PostgreSQL"));
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
    public void PostgresAshlarCleanupDiagnosticsRejectsNullArguments()
    {
        var options = Options.Create(new AshlarCleanupOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresAshlarCleanupDiagnostics(null!, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresAshlarCleanupDiagnostics(options, null!));
        }
    }

    [Test]
    public void AddAshlarPostgresCleanupHostedServiceRegistersHostedService()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgres(GetDataSource());
        services.AddAshlarPostgresCleanupHostedService();
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetServices<IHostedService>().Single(), Is.TypeOf<PostgresAshlarCleanupHostedService>());
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void AddAshlarPostgresCleanupNullArgumentsShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => AshlarPostgresServiceCollectionExtensions.AddAshlarPostgresCleanup(null!));
        Assert.Throws<ArgumentNullException>(() => AshlarPostgresServiceCollectionExtensions.AddAshlarPostgresCleanupHostedService(null!));
    }
}
