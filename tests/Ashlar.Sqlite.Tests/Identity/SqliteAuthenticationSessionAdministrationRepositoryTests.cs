namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteAuthenticationSessionAdministrationRepositoryTests
{
    [Test]
    public void ConstructorRejectsNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new SqliteAuthenticationSessionAdministrationRepository(null!));
    }
}
