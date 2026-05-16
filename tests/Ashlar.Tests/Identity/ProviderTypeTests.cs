using Ashlar.Identity.Models;

namespace Ashlar.Tests.Identity;

internal sealed class ProviderTypeTests
{
    [Test]
    public void DefaultProviderTypeShouldThrowWhenRead()
    {
        var type = default(ProviderType);
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<InvalidOperationException>(() => _ = type.Value);
            Assert.Throws<InvalidOperationException>(() => _ = type.ToString());
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
