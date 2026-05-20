using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Operational;
using Ashlar.Sqlite.Schema;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Sqlite.Tests.DependencyInjection;

internal sealed class AshlarSqliteServiceCollectionExtensionsTests : SqliteTestBase
{
    [Test]
    public async Task AddAshlarSqliteRegistersImplementedRepositoriesOnly()
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
            Assert.That(scope.ServiceProvider.GetRequiredService<IIdentityRepository>(), Is.TypeOf<SqliteIdentityRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IBootstrapStateRepository>(), Is.TypeOf<SqliteBootstrapStateRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationSessionRepository>(), Is.TypeOf<SqliteAuthenticationSessionRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationHandshakeRepository>(), Is.TypeOf<SqliteAuthenticationHandshakeRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IInvitationRepository>(), Is.TypeOf<SqliteInvitationRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IPasskeyChallengeRepository>(), Is.TypeOf<SqlitePasskeyChallengeRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthorizationGrantRepository>(), Is.TypeOf<SqliteAuthorizationGrantRepository>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.TypeOf<SqliteAuthenticationRateLimiter>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarCleanupService>(), Is.TypeOf<SqliteAshlarCleanupService>());
            Assert.That(provider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SqliteSecurityEventSink>());
            Assert.That(provider.GetRequiredService<IUserSecurityEventSummaryRepository>(), Is.SameAs(provider.GetRequiredService<ISecurityEventSink>()));
        }
    }

    [Test]
    public void AddAshlarSqliteRejectsInvalidArguments()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentNullException>(() => AshlarSqliteServiceCollectionExtensions.AddAshlarSqlite(null!, GetConnectionString()));
        Assert.Throws<ArgumentException>(() => services.AddAshlarSqlite(string.Empty));
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
            Assert.DoesNotThrow(() => _ = new SqliteIdentityRepository(connectionProvider));
            Assert.DoesNotThrow(() => _ = new SqliteInvitationRepository(connectionProvider));
            Assert.DoesNotThrow(() => _ = new SqliteAuthenticationHandshakeRepository(connectionProvider));
        }
    }
}
