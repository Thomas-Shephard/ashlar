using Ashlar.Authorization.Abstractions;
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
        services.AddAshlarBootstrap(options =>
        {
            options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
        });

        // Dependencies that must be registered by the user or another helper
        services.AddScoped(_ => new Mock<IIdentityRepository>().Object);
        services.AddScoped(_ => new Mock<IInvitationRepository>().Object);
        services.AddScoped(_ => new Mock<IAuthorizationGrantRepository>().Object);
        services.AddScoped(_ => new Mock<IBootstrapStateRepository>().Object);

        var provider = services.BuildServiceProvider();

        var bootstrapService = provider.GetService<IBootstrapService>();
        Assert.That(bootstrapService, Is.Not.Null);

        var options = provider.GetRequiredService<IOptions<BootstrapOptions>>().Value;
        Assert.That(options.Grants, Has.Count.EqualTo(1));
        Assert.That(options.Grants[0].Role, Is.EqualTo("admin"));
    }
}


