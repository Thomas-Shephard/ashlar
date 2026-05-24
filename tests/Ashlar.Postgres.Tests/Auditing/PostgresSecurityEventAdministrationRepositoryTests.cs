namespace Ashlar.Postgres.Tests.Auditing;

internal sealed class PostgresSecurityEventAdministrationRepositoryTests
{
    [Test]
    public void ConstructorRejectsNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new PostgresSecurityEventAdministrationRepository(null!));
    }
}
