namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresAuthenticationSessionAdministrationRepositoryTests
{
    [Test]
    public void ConstructorRejectsNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new PostgresAuthenticationSessionAdministrationRepository(null!));
    }
}
