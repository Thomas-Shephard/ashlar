using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Ashlar.Identity.RateLimiting.Models;
using Moq;

namespace Ashlar.Tests.DependencyInjection;

internal sealed class AshlarMfaHandshakeServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarMfaHandshakesRegistersServices()
    {
        var services = new ServiceCollection();

        services.AddAshlarMfaHandshakes();

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<AuthenticationHandshakeService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationHandshakeService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationHandshakeCompletionService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<AuthenticationHandshakeOptions>(services, ServiceLifetime.Singleton);
        }
    }

    [Test]
    public void AuthenticationHandshakeServicePublicApiDoesNotExposeFactorCompletion()
    {
        var method = typeof(IAuthenticationHandshakeService).GetMethod(
            "CompleteFactorVerificationAsync",
            [typeof(VerifyAuthenticationHandshakeRequest), typeof(CancellationToken)]);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(method, Is.Null);
            Assert.That(typeof(AuthenticationHandshakeService).IsPublic, Is.False);
        }
    }

    [Test]
    public void AddAshlarMfaHandshakesResolvesPublicAndInternalContractsToSameScopedService()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IAuthenticationHandshakeRepository>());
        services.AddAshlarMfaHandshakes();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var concrete = scope.ServiceProvider.GetRequiredService<AuthenticationHandshakeService>();
        var publicService = scope.ServiceProvider.GetRequiredService<IAuthenticationHandshakeService>();
        var completionService = scope.ServiceProvider.GetRequiredService<IAuthenticationHandshakeCompletionService>();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(publicService, Is.SameAs(concrete));
            Assert.That(completionService, Is.SameAs(concrete));
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

    [Test]
    public void AddAshlarMfaHandshakesRegistersOptionsValidation()
    {
        var services = new ServiceCollection();

        services.AddAshlarMfaHandshakes(options => options.VerificationRateLimit = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AuthenticationHandshakeOptions>>();

        var exception = Assert.Throws<OptionsValidationException>(() => _ = options.Value);
        Assert.That(exception.Failures, Does.Contain("Authentication handshake options are invalid."));
    }

    [Test]
    public void AddAshlarTotpDoesNotRegisterHandshakeOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarTotp();

        Assert.That(services, Has.None.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(IConfigureOptions<AuthenticationHandshakeOptions>)
            || descriptor.ServiceType == typeof(IValidateOptions<AuthenticationHandshakeOptions>)
            || descriptor.ServiceType == typeof(AuthenticationHandshakeOptions)));
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
