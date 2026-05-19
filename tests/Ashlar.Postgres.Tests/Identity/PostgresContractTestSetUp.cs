namespace Ashlar.Postgres.Tests;

using Identity;

[SetUpFixture]
internal sealed class PostgresContractTestSetUp
{
    [OneTimeTearDown]
    public async Task OneTimeTearDown()
    {
        await PostgresContractDatabase.DisposeContainerAsync();
    }
}
