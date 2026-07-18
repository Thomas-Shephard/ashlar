using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Npgsql;

namespace Ashlar.Postgres.Tests.DependencyInjection;

[TestFixture]
internal sealed class AshlarPostgresBootstrapServiceCollectionExtensionsTests
{
    [Test]
    public async Task AddAshlarPostgresBootstrapRegistersRequiredServices()
    {
        var services = new ServiceCollection();
        var connectionString = "Host=localhost;Database=test;Username=test;Password=test";

        services.AddAshlarPostgresBootstrap(connectionString);
        services.AddPostgresProviderContractTestServices();

        // Register other required dependencies for IBootstrapService
        services.AddAshlarProviderScoped(_ => new Mock<IUserRepository>().Object);
        services.AddAshlarProviderScoped(_ => new Mock<IInvitationRepository>().Object);
        services.AddAshlarProviderScoped(_ => new Mock<IAuthorizationGrantRepository>().Object);

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IBootstrapStateRepository>(), Is.InstanceOf<PostgresBootstrapStateRepository>());
            Assert.That(scope.ServiceProvider.GetService<IBootstrapService>(), Is.Not.Null);
        }
    }

    [Test]
    public async Task AddAshlarPostgresBootstrapWithDataSourceRegistersRequiredServices()
    {
        var services = new ServiceCollection();
        await using var dataSource = NpgsqlDataSource.Create("Host=localhost;Database=test;Username=test;Password=test");

        services.AddAshlarPostgresBootstrap(dataSource);
        services.AddPostgresProviderContractTestServices();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<NpgsqlDataSource>(), Is.SameAs(dataSource));
            Assert.That(scope.ServiceProvider.GetRequiredService<IBootstrapStateRepository>(), Is.InstanceOf<PostgresBootstrapStateRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.TypeOf<AshlarDurableTransactionProvider>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>(), Is.TypeOf<PostgresTransactionManagerOwner>());
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void AddAshlarPostgresBootstrapWithDataSourceNullArgumentsShouldThrow()
    {
        var services = new ServiceCollection();
        using var dataSource = NpgsqlDataSource.Create("Host=localhost;Database=test;Username=test;Password=test");

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarPostgresServiceCollectionExtensions.AddAshlarPostgresBootstrap(null!, "conn"));
            Assert.Throws<ArgumentException>(() => services.AddAshlarPostgresBootstrap(string.Empty));
            Assert.Throws<ArgumentNullException>(() => AshlarPostgresServiceCollectionExtensions.AddAshlarPostgresBootstrap(null!, dataSource));
            Assert.Throws<ArgumentNullException>(() => services.AddAshlarPostgresBootstrap((NpgsqlDataSource)null!));
        }
    }

    [Test]
    public void AddAshlarPostgresBootstrapRegistersDurableTransactionProvider()
    {
        var services = new ServiceCollection();
        var connectionString = "Host=localhost;Database=test;Username=test;Password=test";

        services.AddAshlarPostgresBootstrap(connectionString);

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.TypeOf<AshlarDurableTransactionProvider>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IPostgresConnectionProvider>(), Is.TypeOf<PostgresTransactionManagerOwner>());
        }
    }
}
