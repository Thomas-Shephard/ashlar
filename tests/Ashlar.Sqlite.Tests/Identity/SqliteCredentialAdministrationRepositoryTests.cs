namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteCredentialAdministrationRepositoryTests
{
    [Test]
    public void ConstructorRejectsNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new SqliteCredentialAdministrationRepository(null!));
    }
}
