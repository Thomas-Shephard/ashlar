
namespace Ashlar.ProviderContractTests.Identity;

internal abstract class BootstrapStateRepositoryContractTests : ProviderContractFixture
{
    [Test]
    public async Task InitialStatusIsUninitialized()
    {
        await using var scope = CreateAsyncScope();
        var repository = GetBootstrapStateRepository(scope.ServiceProvider);

        Assert.That(await repository.GetBootstrapStatusAsync(), Is.EqualTo(BootstrapStatus.Uninitialized));
    }

    [Test]
    public async Task MarkInitializedSucceedsOnceAndPreservesFirstState()
    {
        await using var scope = CreateAsyncScope();
        var identity = GetIdentityRepository(scope.ServiceProvider);
        var repository = GetBootstrapStateRepository(scope.ServiceProvider);
        var firstUser = await CreateUserAsync(identity, "bootstrap-first@example.com");
        var secondUser = await CreateUserAsync(identity, "bootstrap-second@example.com");
        var firstInitializedAt = new DateTimeOffset(2026, 5, 1, 10, 0, 0, TimeSpan.Zero);

        var first = await repository.MarkAsInitializedAsync(firstUser.Id, firstInitializedAt);
        var second = await repository.MarkAsInitializedAsync(secondUser.Id, firstInitializedAt.AddHours(1));
        var finalStatus = await repository.GetBootstrapStatusAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first, Is.True);
            Assert.That(second, Is.False);
            Assert.That(finalStatus, Is.EqualTo(BootstrapStatus.Initialized));
        }
    }

    [Test]
    public async Task BootstrapInitializationRollsBackWhenProviderSupportsTransactions()
    {
        await using (var scope = CreateAsyncScope())
        {
            var transactionProvider = GetTransactionProvider(scope.ServiceProvider);
            if (transactionProvider == null)
            {
                Assert.Ignore("Provider does not register IAshlarTransactionProvider.");
            }

            var identity = GetIdentityRepository(scope.ServiceProvider);
            var repository = GetBootstrapStateRepository(scope.ServiceProvider);
            var user = await CreateUserAsync(identity, "bootstrap-rollback@example.com");

            await using var transaction = await transactionProvider.BeginTransactionAsync();
            Assert.That(await repository.MarkAsInitializedAsync(user.Id, DateTimeOffset.UtcNow), Is.True);
            await transaction.RollbackAsync();
        }

        await using var verificationScope = CreateAsyncScope();
        var verificationRepository = GetBootstrapStateRepository(verificationScope.ServiceProvider);
        Assert.That(await verificationRepository.GetBootstrapStatusAsync(), Is.EqualTo(BootstrapStatus.Uninitialized));
    }
}


