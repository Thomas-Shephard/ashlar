using Ashlar.Postgres.Schema;
using Npgsql;

namespace Ashlar.Postgres.Tests.Identity;

[TestFixture]
internal sealed class PostgresBootstrapStateRepositoryTests : PostgresTestBase
{
    private PostgresBootstrapStateRepository _repository;
    private SchemaManager _schemaManager;

    [SetUp]
    public async Task SetUp()
    {
        _repository = new PostgresBootstrapStateRepository(new PostgresTransactionManager(GetDataSource()));
        _schemaManager = new SchemaManager(GetDataSource());
        await _schemaManager.InitializeAsync();

        await using var connection = await GetDataSource().OpenConnectionAsync();
        await using var command = new NpgsqlCommand("TRUNCATE ashlar_bootstrap_state, ashlar_users CASCADE", connection);
        await command.ExecuteNonQueryAsync();
    }

    [Test]
    public async Task GetBootstrapStatusAsyncReturnsUninitializedInitially()
    {
        var status = await _repository.GetBootstrapStatusAsync();
        Assert.That(status, Is.EqualTo(BootstrapStatus.Uninitialized));
    }

    [Test]
    public void ConstructorThrowsOnNullConnectionProvider()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresBootstrapStateRepository(null!));
    }

    [Test]
    public async Task MarkAsInitializedAsyncSucceedsAndUpdatesStatus()
    {
        var userId = Guid.NewGuid();
        var initializedAt = DateTimeOffset.UtcNow;

        var identityRepo = new PostgresIdentityRepository(new PostgresTransactionManager(GetDataSource()));
        await identityRepo.CreateUserAsync(new AshlarUser
        {
            Id = userId,
            Email = "admin@example.com",
            IsActive = true
        });

        var result = await _repository.MarkAsInitializedAsync(userId, initializedAt);
        Assert.That(result, Is.True);

        var status = await _repository.GetBootstrapStatusAsync();
        Assert.That(status, Is.EqualTo(BootstrapStatus.Initialized));
    }

    [Test]
    public async Task MarkAsInitializedAsyncFailsIfAlreadyInitialized()
    {
        var userId1 = Guid.NewGuid();
        var userId2 = Guid.NewGuid();
        var identityRepo = new PostgresIdentityRepository(new PostgresTransactionManager(GetDataSource()));

        await identityRepo.CreateUserAsync(new AshlarUser { Id = userId1, Email = "admin1@example.com", IsActive = true });
        await identityRepo.CreateUserAsync(new AshlarUser { Id = userId2, Email = "admin2@example.com", IsActive = true });

        await _repository.MarkAsInitializedAsync(userId1, DateTimeOffset.UtcNow);

        var result = await _repository.MarkAsInitializedAsync(userId2, DateTimeOffset.UtcNow);
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task MarkAsInitializedAsyncHandlesConcurrentAttempts()
    {
        var userId = Guid.NewGuid();
        var identityRepo = new PostgresIdentityRepository(new PostgresTransactionManager(GetDataSource()));
        await identityRepo.CreateUserAsync(new AshlarUser { Id = userId, Email = "admin@example.com", IsActive = true });

        var tasks = Enumerable.Range(0, 10).Select(_ => _repository.MarkAsInitializedAsync(userId, DateTimeOffset.UtcNow)).ToList();

        var results = await Task.WhenAll(tasks);

        Assert.That(results.Count(r => r), Is.EqualTo(1));
    }
}


