using Ashlar.Security.Encryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.DependencyInjection;

internal sealed class AshlarMfaOrchestrationServiceCollectionExtensionsTests
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
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
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

    [Test]
    public void AddAshlarNoMfaPolicyRegistersDefaultPolicyExplicitly()
    {
        var services = new ServiceCollection();

        services.AddAshlarNoMfaPolicy();

        AssertDescriptor<IMfaPolicyEvaluator, MfaPolicyEvaluator>(services, ServiceLifetime.Scoped);
    }

    [Test]
    public void AddAshlarRequireMfaForAllUsersRegistersCompositePolicy()
    {
        var services = new ServiceCollection();
        services.AddAshlarRequireMfaForAllUsers(options => options.RequiredFactors.Add("totp"));

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IMfaPolicyEvaluator>(), Is.TypeOf<CompositeMfaPolicyEvaluator>());
            Assert.That(scope.ServiceProvider.GetRequiredService<RequireMfaForAllUsersPolicyEvaluator>(), Is.Not.Null);
        }
    }

    [Test]
    public void AddAshlarRequireMfaWhenCredentialExistsRegistersCompositePolicy()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddAshlarRequireMfaWhenCredentialExists(options =>
        {
            options.CredentialProviderKeys.Add(new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
            options.RequiredFactors.Add("totp");
        });

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IMfaPolicyEvaluator>(), Is.TypeOf<CompositeMfaPolicyEvaluator>());
            Assert.That(scope.ServiceProvider.GetRequiredService<RequireMfaWhenCredentialExistsPolicyEvaluator>(), Is.Not.Null);
        }
    }

    [Test]
    public void AddAshlarMfaPolicyEvaluatorIsIdempotent()
    {
        var services = new ServiceCollection();

        services.AddAshlarMfaPolicyEvaluator<TestPolicyEvaluator>();
        services.AddAshlarMfaPolicyEvaluator<TestPolicyEvaluator>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.That(scope.ServiceProvider.GetServices<IMfaPolicyEvaluatorComponent>().ToArray(), Has.Length.EqualTo(1));
    }

    private static void AssertDescriptor<TService, TImplementation>(IServiceCollection services, ServiceLifetime lifetime)
    {
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(TService)
            && descriptor.ImplementationType == typeof(TImplementation)
            && descriptor.Lifetime == lifetime));
    }

    private sealed class TestPolicyEvaluator : IMfaPolicyEvaluator
    {
        public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new MfaPolicyEvaluation(false));
        }
    }
}
