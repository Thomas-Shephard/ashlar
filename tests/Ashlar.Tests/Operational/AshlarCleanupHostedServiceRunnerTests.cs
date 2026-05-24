using Ashlar.Operational;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Tests.Operational;

internal sealed class AshlarCleanupHostedServiceRunnerTests
{
    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var services = new ServiceCollection().BuildServiceProvider();
        var scopeFactory = services.GetRequiredService<IServiceScopeFactory>();
        var options = Options.Create(new AshlarCleanupOptions());
        var logger = NullLogger.Instance;

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarCleanupHostedServiceRunner(null!, TimeProvider.System, options, logger));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarCleanupHostedServiceRunner(scopeFactory, null!, options, logger));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarCleanupHostedServiceRunner(scopeFactory, TimeProvider.System, null!, logger));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarCleanupHostedServiceRunner(scopeFactory, TimeProvider.System, options, null!));
        }
    }
}
