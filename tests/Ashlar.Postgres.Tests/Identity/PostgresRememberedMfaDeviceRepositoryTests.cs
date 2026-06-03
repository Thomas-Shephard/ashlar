namespace Ashlar.Postgres.Tests.Identity;

internal sealed class PostgresRememberedMfaDeviceRepositoryTests
{
    [Test]
    public void ConstructorRequiresConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new PostgresRememberedMfaDeviceRepository(null!));
    }
}
