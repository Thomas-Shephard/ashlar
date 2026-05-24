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
    [Test]
    public void AddAshlarPostgresWithDataSourceShouldRegisterServices()
    {
        var services = new ServiceCollection();
        var dataSource = GetDataSource();

        services.AddAshlarPostgres(dataSource);
        var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<NpgsqlDataSource>(), Is.Not.Null);
            Assert.That(provider.GetService<TimeProvider>(), Is.Not.Null);
            Assert.That(provider.GetService<IAshlarSchemaDiagnostics>(), Is.TypeOf<PostgresSchemaDiagnostics>());
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.Repositories.IUserRepository>(), Is.TypeOf<PostgresUserRepository>());
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.Repositories.ICredentialRepository>(), Is.TypeOf<PostgresCredentialRepository>());
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.Repositories.ICredentialAdministrationRepository>(), Is.TypeOf<PostgresCredentialAdministrationRepository>());
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.Repositories.IAuthenticationSessionAdministrationRepository>(), Is.TypeOf<PostgresAuthenticationSessionAdministrationRepository>());
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.Repositories.IAuthenticationSessionRepository>(), Is.TypeOf<PostgresAuthenticationSessionRepository>());
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.Repositories.IAuthenticationHandshakeRepository>(), Is.TypeOf<PostgresAuthenticationHandshakeRepository>());
            Assert.That(provider.GetService<SchemaManager>(), Is.Not.Null);
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
        }
    }

    [Test]
    public void InitializeAshlarPostgresSchemaAsyncNullProviderShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(async () => await AshlarPostgresServiceCollectionExtensions.InitializeAshlarPostgresSchemaAsync(null!));
    }

    [Test]
    public void AddAshlarPostgresCleanupRegistersCleanupService()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgres(GetDataSource());
        services.AddAshlarPostgresCleanup(options => options.BatchSize = 42);
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarCleanupService>(), Is.TypeOf<PostgresAshlarCleanupService>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarCleanupDiagnostics>(), Is.TypeOf<PostgresAshlarCleanupDiagnostics>());
            Assert.That(provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AshlarCleanupOptions>>().Value.BatchSize, Is.EqualTo(42));
        }
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
            Assert.That(result.ProviderName, Is.EqualTo("Postgres"));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.OptionsValid, Is.True);
            Assert.That(result.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(30)));
            Assert.That(result.BatchSize, Is.EqualTo(42));
            Assert.That(result.MaxBatchesPerRun, Is.EqualTo(2));
            Assert.That(result.EnabledCategoryCount, Is.EqualTo(17));
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
