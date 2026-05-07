using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Encryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.DependencyInjection;

public class AshlarMfaOrchestrationServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarMfaOrchestrationRegistersServicesWithExpectedLifetimes()
    {
        var services = new ServiceCollection();

        services.AddAshlarMfaOrchestration();

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<IMfaPolicyEvaluator, MfaPolicyEvaluator>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationOrchestrator, AuthenticationOrchestrator>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationHandshakeService, AuthenticationHandshakeService>(services, ServiceLifetime.Scoped);
        }
    }

    [Test]
    public void AddAshlarMfaOrchestrationResolvesOrchestratorWhenRequiredDependenciesArePresent()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IIdentityRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationHandshakeRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddAshlarMfaOrchestration();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var orchestrator = scope.ServiceProvider.GetRequiredService<IAuthenticationOrchestrator>();

        Assert.That(orchestrator, Is.TypeOf<AuthenticationOrchestrator>());
    }

    [Test]
    public void AddAshlarMfaOrchestrationConfiguresOptions()
    {
        var services = new ServiceCollection();
        bool configured = false;
        services.AddAshlarMfaOrchestration(_ => configured = true);

        using var provider = services.BuildServiceProvider();
        _ = provider.GetRequiredService<IOptions<MfaOrchestrationOptions>>().Value;

        Assert.That(configured, Is.True);
    }

    private static void AssertDescriptor<TService, TImplementation>(IServiceCollection services, ServiceLifetime lifetime)
    {
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(TService)
            && descriptor.ImplementationType == typeof(TImplementation)
            && descriptor.Lifetime == lifetime));
    }
}
