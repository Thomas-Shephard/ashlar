namespace Ashlar.Tests.Identity.Features.Authentication;

internal sealed class AuthenticationProviderKeyTests
{
    [Test]
    public void ConstructorShouldTrimProviderName()
    {
        var key = new AuthenticationProviderKey(ProviderType.Oidc, " Google ");

        Assert.That(key.Name, Is.EqualTo("Google"));
    }

    [Test]
    public void ConstructorShouldRejectNullOrWhiteSpaceProviderName()
    {
        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => _ = new AuthenticationProviderKey(ProviderType.Oidc, null!));
            Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderKey(ProviderType.Oidc, ""));
            Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderKey(ProviderType.Oidc, " "));
        }
    }

    [Test]
    public void ConstructorShouldRejectDefaultProviderType()
    {
        Assert.Throws<ArgumentException>(() => _ = new AuthenticationProviderKey(default, "Google"));
    }

    [Test]
    public void EqualityShouldIgnoreProviderNameCase()
    {
        var first = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        var second = new AuthenticationProviderKey(ProviderType.Oidc, "google");

        Assert.That(first, Is.EqualTo(second));
    }

    [Test]
    public void EqualityShouldUseProviderType()
    {
        var oidc = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        var oauth = new AuthenticationProviderKey(ProviderType.OAuth, "Google");

        Assert.That(oidc, Is.Not.EqualTo(oauth));
    }

    [Test]
    public void DefaultKeyShouldHaveEmptyName()
    {
        var key = default(AuthenticationProviderKey);
        Assert.That(key.Name, Is.EqualTo(string.Empty));
    }

    [Test]
    public void DefaultKeyShouldHaveDiagnosticToString()
    {
        var key = default(AuthenticationProviderKey);

        Assert.That(key.ToString(), Is.EqualTo("<uninitialized provider>"));
    }

    [Test]
    public void DefaultKeyShouldUseStorageFallbackTypeValue()
    {
        var key = default(AuthenticationProviderKey);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(key.StorageTypeValue, Is.EqualTo(ProviderType.StorageFallbackValue));
            Assert.That(key.Type.IsStorageFallback, Is.True);
            Assert.That(key.IsInitialized, Is.False);
            Assert.That(key.IsConfigured, Is.False);
            Assert.That(key.ToString(), Is.EqualTo("<uninitialized provider>"));
        }
    }

    [Test]
    public void StorageFallbackProviderShouldBeAddressableInFormattingAndStorageShapes()
    {
        var key = new AuthenticationProviderKey((ProviderType)ProviderType.StorageFallbackValue, "Missing");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(key.Type.IsStorageFallback, Is.True);
            Assert.That(key.IsInitialized, Is.True);
            Assert.That(key.IsConfigured, Is.False);
            Assert.That(key.StorageTypeValue, Is.EqualTo(ProviderType.StorageFallbackValue));
            Assert.That(key.ToString(), Is.EqualTo($"{ProviderType.StorageFallbackValue}:Missing"));
            Assert.That(AuthenticationProviderKey.GetStorageTypeValue(key), Is.EqualTo(ProviderType.StorageFallbackValue));
        }
    }

    [Test]
    public void ConfiguredProviderShouldBeInitializedAndConfigured()
    {
        var key = new AuthenticationProviderKey(ProviderType.Oidc, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(key.Type.IsStorageFallback, Is.False);
            Assert.That(key.IsInitialized, Is.True);
            Assert.That(key.IsConfigured, Is.True);
            Assert.That(key.StorageTypeValue, Is.EqualTo("OIDC"));
        }
    }

    [Test]
    public void GetStorageTypeValueShouldHandleMissingDefaultAndInitializedProviders()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AuthenticationProviderKey.GetStorageTypeValue(null), Is.Null);
            Assert.That(AuthenticationProviderKey.GetStorageTypeValue(default(AuthenticationProviderKey)), Is.EqualTo(ProviderType.StorageFallbackValue));
            Assert.That(AuthenticationProviderKey.GetStorageTypeValue(new AuthenticationProviderKey(ProviderType.Oidc, "Google")), Is.EqualTo("OIDC"));
        }
    }

    [Test]
    public void PersistedProviderKeyShouldRoundTripMissingFallbackAndConfiguredProviders()
    {
        var missing = PersistedAuthenticationProviderKey.FromProvider(null);
        var fallback = PersistedAuthenticationProviderKey.FromProvider(default(AuthenticationProviderKey));
        var configuredProvider = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        var configured = PersistedAuthenticationProviderKey.FromProvider(configuredProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.Kind, Is.EqualTo(PersistedAuthenticationProviderKind.None));
            Assert.That(missing.ToProviderKey(), Is.Null);
            Assert.That(fallback.Kind, Is.EqualTo(PersistedAuthenticationProviderKind.StorageFallback));
            Assert.That(fallback.ProviderTypeValue, Is.EqualTo(ProviderType.StorageFallbackValue));
            Assert.That(fallback.ProviderName, Is.EqualTo(string.Empty));
            Assert.That(fallback.ToProviderKey(), Is.EqualTo(default(AuthenticationProviderKey)));
            Assert.That(configured.Kind, Is.EqualTo(PersistedAuthenticationProviderKind.Configured));
            Assert.That(configured.ProviderTypeValue, Is.EqualTo("OIDC"));
            Assert.That(configured.ProviderName, Is.EqualTo("Google"));
            Assert.That(configured.ToProviderKey(), Is.EqualTo(configuredProvider));
        }
    }

    [Test]
    public void PersistedProviderKeyShouldMarkIncompleteNonFallbackValues()
    {
        var nullName = new PersistedAuthenticationProviderKey("LOCAL", null);
        var emptyName = new PersistedAuthenticationProviderKey("LOCAL", string.Empty);
        var fallbackWithName = new PersistedAuthenticationProviderKey(ProviderType.StorageFallbackValue, "missing");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(nullName.Kind, Is.EqualTo(PersistedAuthenticationProviderKind.Incomplete));
            Assert.That(nullName.ToProviderKey(), Is.Null);
            Assert.That(emptyName.Kind, Is.EqualTo(PersistedAuthenticationProviderKind.Incomplete));
            Assert.That(emptyName.ToProviderKey(), Is.Null);
            Assert.That(new PersistedAuthenticationProviderKey(ProviderType.StorageFallbackValue, null).ToProviderKey(), Is.EqualTo(default(AuthenticationProviderKey)));
            Assert.That(new PersistedAuthenticationProviderKey(ProviderType.StorageFallbackValue, " ").ToProviderKey(), Is.EqualTo(default(AuthenticationProviderKey)));
            Assert.That(fallbackWithName.Kind, Is.EqualTo(PersistedAuthenticationProviderKind.StorageFallback));
            Assert.That(fallbackWithName.ToProviderKey(), Is.EqualTo(default(AuthenticationProviderKey)));
        }
    }

    [Test]
    public void HappyPathToStringShouldWork()
    {
        var key = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        Assert.That(key.ToString(), Is.EqualTo("OIDC:Google"));
    }
}
