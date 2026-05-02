using Ashlar.Postgres.Schema;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Ashlar.Postgres.Tests.DependencyInjection;

public sealed class AshlarPostgresServiceCollectionExtensionsTests : PostgresTestBase
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
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.IIdentityRepository>(), Is.TypeOf<PostgresIdentityRepository>());
            Assert.That(provider.GetService<Ashlar.Identity.Abstractions.IAuthenticationSessionRepository>(), Is.TypeOf<PostgresAuthenticationSessionRepository>());
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
}
