namespace Ashlar.Sqlite.Tests.Auditing;

internal sealed class SqliteSecurityEventAdministrationRepositoryTests
{
    [Test]
    public void ConstructorRejectsNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventAdministrationRepository(null!));
    }
}
