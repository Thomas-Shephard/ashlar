namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresUserAdministrationRepositoryTests
{
    [Test]
    public void ConstructorRejectsNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new PostgresUserAdministrationRepository(null!));
    }
}
