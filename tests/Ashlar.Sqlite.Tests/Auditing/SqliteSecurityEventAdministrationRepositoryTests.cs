namespace Ashlar.Sqlite.Tests.Auditing;

internal sealed class SqliteSecurityEventAdministrationRepositoryTests
{
    [Test]
    public void ConstructorRejectsNullConnectionProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new SqliteSecurityEventAdministrationRepository(null!));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("[]")]
    [TestCase("{}")]
    [TestCase("{")]
    public void ParsePropertiesReturnsNullForUnsafeOrEmptyPayloads(string? json)
    {
        Assert.That(SqliteSecurityEventAdministrationRepository.ParseProperties(json), Is.Null);
    }

    [Test]
    public void ParsePropertiesReturnsOnlyStringProperties()
    {
        var properties = SqliteSecurityEventAdministrationRepository.ParseProperties("""{"safe":"value","number":1,"empty":""}""");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(properties, Does.ContainKey("safe").WithValue("value"));
            Assert.That(properties, Does.ContainKey("empty").WithValue(string.Empty));
            Assert.That(properties, Does.Not.ContainKey("number"));
        }
    }
}
