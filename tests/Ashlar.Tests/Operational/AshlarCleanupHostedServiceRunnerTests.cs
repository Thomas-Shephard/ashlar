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
        static Task<AshlarCleanupResult> Cleanup(IServiceProvider _, CancellationToken __) =>
            Task.FromResult(AshlarCleanupResult.Empty);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarCleanupHostedServiceRunner(null!, TimeProvider.System, options, logger, Cleanup));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarCleanupHostedServiceRunner(scopeFactory, null!, options, logger, Cleanup));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarCleanupHostedServiceRunner(scopeFactory, TimeProvider.System, null!, logger, Cleanup));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarCleanupHostedServiceRunner(scopeFactory, TimeProvider.System, options, null!, Cleanup));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarCleanupHostedServiceRunner(scopeFactory, TimeProvider.System, options, logger, null!));
        }
    }
}
