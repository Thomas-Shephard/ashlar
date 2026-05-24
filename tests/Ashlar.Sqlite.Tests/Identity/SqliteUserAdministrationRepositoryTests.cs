namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteUserAdministrationRepositoryTests
{
    [Test]
    public void ConstructorRejectsNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new SqliteUserAdministrationRepository(null!));
    }
}
