using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Tests.DependencyInjection;

public sealed class AshlarPostgresEmailOutboxServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarPostgresEmailOutboxRegistersRequiredServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresEmailOutbox();

        var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<IEmailSender>(), Is.InstanceOf<PostgresEmailOutboxSender>());
            Assert.That(provider.GetService<IOptions<PostgresEmailOutboxOptions>>(), Is.Not.Null);
        }
    }

    [Test]
    public void AddAshlarPostgresEmailOutboxConfiguresOptions()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresEmailOutbox(options =>
        {
            options.BatchSize = 123;
        });

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PostgresEmailOutboxOptions>>().Value;

        Assert.That(options.BatchSize, Is.EqualTo(123));
    }

    [Test]
    public void AddAshlarPostgresEmailOutboxHostedServiceRegistersBackgroundService()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresEmailOutboxHostedService<TestTransport>();

        var provider = services.BuildServiceProvider();
        var hostedServices = provider.GetServices<IHostedService>().ToList();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(hostedServices.Any(s => s is PostgresEmailOutboxDispatcher<TestTransport>), Is.True);
            Assert.That(provider.GetService<IEmailSender>(), Is.InstanceOf<PostgresEmailOutboxSender>());
        }
    }

    private sealed class TestTransport : IEmailTransport
    {
        public Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
