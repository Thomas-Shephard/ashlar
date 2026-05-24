namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresCredentialAdministrationRepositoryTests
{
    [Test]
    public void ConstructorRejectsNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new PostgresCredentialAdministrationRepository(null!));
    }
}
