using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Tests.DependencyInjection;

public class AshlarMfaHandshakeServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarMfaHandshakesRegistersServices()
    {
        var services = new ServiceCollection();

        services.AddAshlarMfaHandshakes();

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<IAuthenticationHandshakeService, AuthenticationHandshakeService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<AuthenticationHandshakeOptions>(services, ServiceLifetime.Singleton);
        }
    }

    [Test]
    public void AddAshlarMfaHandshakesConfiguresOptions()
    {
        var services = new ServiceCollection();
        var expiry = TimeSpan.FromHours(1);

        services.AddAshlarMfaHandshakes(options => options.Expiry = expiry);

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<AuthenticationHandshakeOptions>().Expiry, Is.EqualTo(expiry));
    }

    private static void AssertDescriptor<TService, TImplementation>(IServiceCollection services, ServiceLifetime lifetime)
    {
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(TService)
            && descriptor.ImplementationType == typeof(TImplementation)
            && descriptor.Lifetime == lifetime));
    }

    private static void AssertDescriptor<TService>(IServiceCollection services, ServiceLifetime lifetime)
    {
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(TService)
            && descriptor.Lifetime == lifetime));
    }
}
