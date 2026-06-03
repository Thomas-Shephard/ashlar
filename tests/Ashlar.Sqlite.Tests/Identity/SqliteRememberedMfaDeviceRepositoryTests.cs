namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteRememberedMfaDeviceRepositoryTests
{
    [Test]
    public void ConstructorRequiresConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new SqliteRememberedMfaDeviceRepository(null!));
    }
}
