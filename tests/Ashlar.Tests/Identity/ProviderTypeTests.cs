using Ashlar.Identity.Models;

namespace Ashlar.Tests.Identity;

public class ProviderTypeTests
{
    [Test]
    public void DefaultProviderTypeShouldReturnEmptyString()
    {
        var type = default(ProviderType);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(type.Value, Is.EqualTo(string.Empty));
            Assert.That(type.ToString(), Is.EqualTo(string.Empty));
        }
    }

    [Test]
    public void ImplicitConversionToStringShouldWork()
    {
        string value = ProviderType.Local;
        Assert.That(value, Is.EqualTo("LOCAL"));
    }

    [Test]
    public void ImplicitConversionFromStringShouldWork()
    {
        ProviderType type = "Custom";
        Assert.That(type.Value, Is.EqualTo("CUSTOM"));
    }

    [Test]
    public void ConstructorShouldThrowOnNullOrWhiteSpace()
    {
        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => { _ = (ProviderType)null!; });
            Assert.Throws<ArgumentException>(() => { _ = (ProviderType)""; });
            Assert.Throws<ArgumentException>(() => { _ = (ProviderType)" "; });
        }
    }

    [Test]
    public void EqualityShouldWork()
    {
        var type1 = (ProviderType)"OIDC";
        var type2 = ProviderType.Oidc;
        Assert.That(type1, Is.EqualTo(type2));
    }
}
