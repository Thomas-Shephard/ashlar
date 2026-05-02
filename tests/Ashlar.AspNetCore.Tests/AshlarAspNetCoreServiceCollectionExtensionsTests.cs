using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.AspNetCore.Tests;

public sealed class AshlarAspNetCoreServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarAspNetCoreSessionsShouldRejectHostPrefixedCookieWithDomain()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddAshlarAspNetCoreSessions(options =>
        {
            options.Cookie.Domain = "example.com";
        }));
    }

    [Test]
    public void AddAshlarAspNetCoreSessionsShouldRejectHostPrefixedCookieWithNonRootPath()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddAshlarAspNetCoreSessions(options =>
        {
            options.Cookie.Path = "/app";
        }));
    }

    [Test]
    public void AddAshlarAspNetCoreSessionsShouldRejectHostPrefixedCookieWithoutAlwaysSecurePolicy()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddAshlarAspNetCoreSessions(options =>
        {
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        }));
    }

    [Test]
    public void AddAshlarAspNetCoreSessionsShouldAllowNonHostPrefixedCookieCustomization()
    {
        var services = new ServiceCollection();

        Assert.DoesNotThrow(() => services.AddAshlarAspNetCoreSessions(options =>
        {
            options.CookieName = "Ashlar.Session";
            options.Cookie.Domain = "example.com";
            options.Cookie.Path = "/app";
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        }));
    }
}
