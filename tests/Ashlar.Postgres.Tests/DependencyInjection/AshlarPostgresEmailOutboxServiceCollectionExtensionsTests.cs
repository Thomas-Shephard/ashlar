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
            Assert.That(provider.GetService<TimeProvider>(), Is.Not.Null);
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
            Assert.That(hostedServices.Any(s => s is PostgresEmailOutboxHostedService), Is.True);
            Assert.That(provider.GetService<IEmailOutboxDispatcher>(), Is.InstanceOf<PostgresEmailOutboxDispatcher<TestTransport>>());
            Assert.That(provider.GetService<IEmailSender>(), Is.InstanceOf<PostgresEmailOutboxSender>());
        }
    }

    [Test]
    public void AddAshlarPostgresEmailOutboxRegistersConcreteTransport()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresEmailOutbox<TestTransport>();

        Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(TestTransport)), Is.True);
    }

    [Test]
    public void AddAshlarPostgresEmailOutboxDoesNotRegisterAbstractTransport()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresEmailOutbox<AbstractTransport>();

        Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(AbstractTransport)), Is.False);
    }

    [Test]
    public void AddAshlarPostgresEmailOutboxDoesNotRegisterInterfaceTransport()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresEmailOutbox<IEmailTransport>();

        Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IEmailTransport)), Is.False);
    }

    private abstract class AbstractTransport : IEmailTransport
    {
        public abstract Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default);
    }

    private sealed class TestTransport : IEmailTransport
    {
        public Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
