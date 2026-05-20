using System.Diagnostics.CodeAnalysis;
using Ashlar.Operational;
using Ashlar.Postgres.Schema;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.Repositories.IIdentityRepository>(), Is.TypeOf<PostgresIdentityRepository>());
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.Repositories.IAuthenticationSessionRepository>(), Is.TypeOf<PostgresAuthenticationSessionRepository>());
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.Repositories.IAuthenticationHandshakeRepository>(), Is.TypeOf<PostgresAuthenticationHandshakeRepository>());
            Assert.That(provider.GetService<SchemaManager>(), Is.Not.Null);
        }
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
            Assert.That(provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AshlarCleanupOptions>>().Value.BatchSize, Is.EqualTo(42));
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
