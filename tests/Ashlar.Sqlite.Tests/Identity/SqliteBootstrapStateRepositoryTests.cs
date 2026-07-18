using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteBootstrapStateRepositoryTests : SqliteTestBase
{
    private ServiceProvider _serviceProvider = null!;

    [SetUp]
    public async Task SetUp()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddSqliteProviderContractTestServices();
        _serviceProvider = services.BuildServiceProvider();
        await _serviceProvider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _serviceProvider.DisposeAsync();
    }

    [Test]
    public void ConstructorThrowsOnNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new SqliteBootstrapStateRepository(null!));
    }

    [Test]
    public async Task BootstrapStatusStartsUninitializedThenInitializesOnce()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var identity = scope.ServiceProvider.GetRequiredService<IUserRepository>();
        var repository = scope.ServiceProvider.GetRequiredService<IBootstrapStateRepository>();
        var user = new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = "admin@example.com", AccountState = UserAccountState.Active };
        await identity.CreateUserAsync(user);

        var initial = await repository.GetBootstrapStatusAsync();
        var first = await repository.MarkAsInitializedAsync(user.Id, DateTimeOffset.UtcNow);
        var second = await repository.MarkAsInitializedAsync(user.Id, DateTimeOffset.UtcNow.AddMinutes(1));
        var final = await repository.GetBootstrapStatusAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(initial, Is.EqualTo(BootstrapStatus.Uninitialized));
            Assert.That(first, Is.True);
            Assert.That(second, Is.False);
            Assert.That(final, Is.EqualTo(BootstrapStatus.Initialized));
        }
    }

    [Test]
    public async Task BootstrapWriteRollsBackWithTransaction()
    {
        await using (var scope = _serviceProvider.CreateAsyncScope())
        {
            var identity = scope.ServiceProvider.GetRequiredService<IUserRepository>();
            var repository = scope.ServiceProvider.GetRequiredService<IBootstrapStateRepository>();
            var transactions = scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>();
            var user = new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = "rollback-admin@example.com", AccountState = UserAccountState.Active };
            await identity.CreateUserAsync(user);

            await using var transaction = await transactions.BeginTransactionAsync();
            Assert.That(await repository.MarkAsInitializedAsync(user.Id, DateTimeOffset.UtcNow), Is.True);
            await transaction.RollbackAsync();
        }

        await using var verificationScope = _serviceProvider.CreateAsyncScope();
        var verificationRepository = verificationScope.ServiceProvider.GetRequiredService<IBootstrapStateRepository>();
        Assert.That(await verificationRepository.GetBootstrapStatusAsync(), Is.EqualTo(BootstrapStatus.Uninitialized));
    }
}
