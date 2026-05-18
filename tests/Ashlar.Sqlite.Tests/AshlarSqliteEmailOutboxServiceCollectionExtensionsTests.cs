using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Tests;

internal sealed class AshlarSqliteEmailOutboxServiceCollectionExtensionsTests
{
    [Test]
    public async Task AddAshlarSqliteEmailOutboxSenderRegistersRequiredServices()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite("Data Source=:memory:");
        services.AddAshlarSqliteEmailOutboxSender(options => options.BatchSize = 123);

        await using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<IEmailSender>(), Is.InstanceOf<SqliteEmailOutboxSender>());
            Assert.That(provider.GetRequiredService<IOptions<SqliteEmailOutboxOptions>>().Value.BatchSize, Is.EqualTo(123));
            Assert.That(provider.GetService<TimeProvider>(), Is.Not.Null);
        }
    }

    [Test]
    public async Task AddAshlarSqliteEmailOutboxDispatcherRegistersDispatcherAndTransport()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite("Data Source=:memory:");
        services.AddAshlarSqliteEmailOutboxDispatcher<TestTransport>();

        await using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetService<IEmailOutboxDispatcher>(), Is.InstanceOf<SqliteEmailOutboxDispatcher<TestTransport>>());
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(TestTransport)), Is.True);
        }
    }

    [Test]
    public void AddAshlarSqliteEmailOutboxDispatcherDoesNotRegisterAbstractOrInterfaceTransport()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqliteEmailOutboxDispatcher<AbstractTransport>();
        services.AddAshlarSqliteEmailOutboxDispatcher<IEmailTransport>();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(AbstractTransport)), Is.False);
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IEmailTransport)), Is.False);
        }
    }

    [Test]
    public async Task AddAshlarSqliteEmailOutboxHostedServiceRegistersBackgroundService()
    {
        var services = new ServiceCollection();
        services.AddAshlarSqlite("Data Source=:memory:");
        services.AddAshlarSqliteEmailOutboxHostedService<TestTransport>();

        await using var provider = services.BuildServiceProvider();
        var hostedServices = provider.GetServices<IHostedService>().ToList();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(hostedServices.Any(service => service is SqliteEmailOutboxHostedService<TestTransport>), Is.True);
            Assert.That(provider.GetService<IEmailOutboxDispatcher>(), Is.InstanceOf<SqliteEmailOutboxDispatcher<TestTransport>>());
            Assert.That(provider.GetService<IEmailSender>(), Is.InstanceOf<SqliteEmailOutboxSender>());
        }
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
