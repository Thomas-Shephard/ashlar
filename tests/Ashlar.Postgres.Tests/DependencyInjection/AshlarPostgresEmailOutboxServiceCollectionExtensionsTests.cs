using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Tests.DependencyInjection;

internal sealed class AshlarPostgresEmailOutboxServiceCollectionExtensionsTests
{
    [Test]
    public async Task AddAshlarPostgresEmailOutboxSenderRegistersRequiredServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresEmailOutboxSender();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetService<IEmailSender>(), Is.InstanceOf<PostgresEmailOutboxSender>());
            Assert.That(provider.GetService<IOptions<PostgresEmailOutboxOptions>>(), Is.Not.Null);
            Assert.That(provider.GetService<TimeProvider>(), Is.Not.Null);
        }
    }

    [Test]
    public async Task AddAshlarPostgresEmailOutboxSenderConfiguresOptions()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresEmailOutboxSender(options =>
        {
            options.BatchSize = 123;
        });

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PostgresEmailOutboxOptions>>().Value;

        Assert.That(options.BatchSize, Is.EqualTo(123));
    }

    [Test]
    public void AddAshlarPostgresEmailOutboxSenderValidatesOptionsOnStart()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresEmailOutboxSender(options => options.BatchSize = 0);

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(PostgresEmailOutboxOptions)));
    }

    [Test]
    public async Task AddAshlarPostgresEmailOutboxDispatcherRegistersDispatcher()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresEmailOutboxDispatcher<TestTransport>();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetService<IEmailOutboxDispatcher>(), Is.InstanceOf<PostgresEmailOutboxDispatcher<TestTransport>>());
            Assert.That(services.Any(descriptor => descriptor.ServiceType.IsPublic && descriptor.ServiceType.GetMethod("ProcessBatchAsync") != null), Is.False);
            Assert.That(typeof(AshlarPostgresServiceCollectionExtensions).GetMethod("AddAshlarPostgresEmailOutboxDispatcher"), Is.Null);
        }
    }

    [Test]
    public async Task AddAshlarPostgresEmailOutboxHostedServiceRegistersBackgroundService()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarPostgres("Host=localhost;Database=test");
        services.AddAshlarPostgresEmailOutboxHostedService<TestTransport>();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var hostedServices = provider.GetServices<IHostedService>().ToList();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(hostedServices.Any(s => s is PostgresEmailOutboxHostedService), Is.True);
            Assert.That(scope.ServiceProvider.GetService<IEmailOutboxDispatcher>(), Is.InstanceOf<PostgresEmailOutboxDispatcher<TestTransport>>());
            Assert.That(scope.ServiceProvider.GetService<IEmailSender>(), Is.InstanceOf<PostgresEmailOutboxSender>());
        }
    }

    [Test]
    public void AddAshlarPostgresEmailOutboxDispatcherRegistersConcreteTransport()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresEmailOutboxDispatcher<TestTransport>();

        Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(TestTransport)), Is.True);
    }

    [Test]
    public void AddAshlarPostgresEmailOutboxDispatcherDoesNotRegisterAbstractTransport()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresEmailOutboxDispatcher<AbstractTransport>();

        Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(AbstractTransport)), Is.False);
    }

    [Test]
    public void AddAshlarPostgresEmailOutboxDispatcherDoesNotRegisterInterfaceTransport()
    {
        var services = new ServiceCollection();

        services.AddAshlarPostgresEmailOutboxDispatcher<IEmailTransport>();

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
