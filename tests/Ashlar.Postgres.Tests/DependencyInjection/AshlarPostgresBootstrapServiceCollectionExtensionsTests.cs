using System.Diagnostics.CodeAnalysis;
using Ashlar.Authorization.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Npgsql;

namespace Ashlar.Postgres.Tests.DependencyInjection;

[TestFixture]
internal sealed class AshlarPostgresBootstrapServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarPostgresBootstrapRegistersRequiredServices()
    {
        var services = new ServiceCollection();
        var connectionString = "Host=localhost;Database=test;Username=test;Password=test";

        services.AddAshlarPostgresBootstrap(connectionString);

        // Register other required dependencies for IBootstrapService
        services.AddScoped(_ => new Mock<IUserRepository>().Object);
        services.AddScoped(_ => new Mock<IInvitationRepository>().Object);
        services.AddScoped(_ => new Mock<IAuthorizationGrantRepository>().Object);

        var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<IBootstrapStateRepository>(), Is.InstanceOf<PostgresBootstrapStateRepository>());
            Assert.That(provider.GetService<IBootstrapService>(), Is.Not.Null);
        }
    }

    [Test]
    public async Task AddAshlarPostgresBootstrapWithDataSourceRegistersRequiredServices()
    {
        var services = new ServiceCollection();
        var dataSource = NpgsqlDataSource.Create("Host=localhost;Database=test;Username=test;Password=test");

        services.AddAshlarPostgresBootstrap(dataSource);

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<NpgsqlDataSource>(), Is.SameAs(dataSource));
            Assert.That(scope.ServiceProvider.GetRequiredService<IBootstrapStateRepository>(), Is.InstanceOf<PostgresBootstrapStateRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>(), Is.TypeOf<PostgresTransactionManager>());
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void AddAshlarPostgresBootstrapWithDataSourceNullArgumentsShouldThrow()
    {
        var services = new ServiceCollection();
        var dataSource = NpgsqlDataSource.Create("Host=localhost;Database=test;Username=test;Password=test");

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarPostgresServiceCollectionExtensions.AddAshlarPostgresBootstrap(null!, dataSource));
            Assert.Throws<ArgumentNullException>(() => services.AddAshlarPostgresBootstrap((NpgsqlDataSource)null!));
        }
    }

    [Test]
    public async Task AddAshlarPostgresBootstrapReplacesNullTransactionProvider()
    {
        var services = new ServiceCollection();
        var connectionString = "Host=localhost;Database=test;Username=test;Password=test";

        services.AddAshlarPostgresBootstrap(connectionString);

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>(), Is.TypeOf<PostgresTransactionManager>());
    }
}
