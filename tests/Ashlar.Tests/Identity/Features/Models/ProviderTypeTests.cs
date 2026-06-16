namespace Ashlar.Tests.Identity.Features.Models;

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
            Assert.That(type.StorageValue, Is.EqualTo(ProviderType.StorageFallbackValue));
            Assert.That(type.IsStorageFallback, Is.True);
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

    [Test]
    public void StorageValueShouldReturnInitializedValue()
    {
        Assert.That(ProviderType.Oidc.StorageValue, Is.EqualTo("OIDC"));
    }

    [Test]
    public void ConfiguredProviderTypeShouldNotBeStorageFallback()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(ProviderType.Oidc.IsStorageFallback, Is.False);
            Assert.That(default(ProviderType).IsStorageFallback, Is.True);
        }
    }
}
