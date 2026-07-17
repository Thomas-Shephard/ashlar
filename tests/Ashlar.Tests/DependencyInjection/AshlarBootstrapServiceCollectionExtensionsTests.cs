using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.DependencyInjection;

[TestFixture]
internal sealed class AshlarBootstrapServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarBootstrapRegistersRequiredServices()
    {
        var services = new ServiceCollection();
        services.AddAshlarBootstrap();

        // Dependencies that must be registered by the user or another helper
        var users = new Mock<IUserRepository>().Object;
        var bootstrap = new Mock<IBootstrapStateRepository>().Object;
        var composition = new DurableSecurityMutationTestComposition(participants: [users, bootstrap]);
        services.AddAshlarProviderScoped(_ => users);
        services.AddScoped(_ => composition.Transactions);
        services.AddAshlarProviderScoped(_ => bootstrap);

        var provider = services.BuildServiceProvider();

        var bootstrapService = provider.GetService<IBootstrapService>();

        var options = provider.GetRequiredService<IOptions<BootstrapOptions>>().Value;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(bootstrapService, Is.Not.Null);
            Assert.That(options.Grants, Is.Empty);
        }
    }

    [Test]
    public void AddAshlarBootstrapWithGrantsRequiresAuthorizationService()
    {
        var services = new ServiceCollection();
        services.AddAshlarBootstrap(options =>
        {
            options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
        });

        var users = new Mock<IUserRepository>().Object;
        var bootstrap = new Mock<IBootstrapStateRepository>().Object;
        var composition = new DurableSecurityMutationTestComposition(participants: [users, bootstrap]);
        services.AddAshlarProviderScoped(_ => users);
        services.AddScoped(_ => composition.Transactions);
        services.AddAshlarProviderScoped(_ => bootstrap);

        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(() => _ = provider.GetService<IBootstrapService>());

        Assert.That(exception?.Message, Does.Contain("built-in authorization"));
    }

    [Test]
    public void AddAshlarBootstrapValidatesOptions()
    {
        var services = new ServiceCollection();
        services.AddAshlarBootstrap(options =>
        {
            options.Grants.Add(new BootstrapGrantTemplate());
        });

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() =>
            _ = provider.GetRequiredService<IOptions<BootstrapOptions>>().Value);

        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(BootstrapOptions)));
    }
}
