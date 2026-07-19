using System.Net;
using System.Net.Sockets;
using System.Text;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Operational.Diagnostics;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Testing.DependencyInjection;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarWebhooksServiceCollectionExtensionsTests
{
    private const string ValidSecret = "0123456789abcdef0123456789abcdef";
    [Test]
    public void AddAshlarSecurityEventWebhooksRegistersHandlerAndOptions()
    {
        var services = new ServiceCollection();
        var configuredHttpClient = false;

        services.AddAshlarSecurityEventWebhooks(
            options =>
            {
                options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
                {
                    Name = "audit",
                    Uri = new Uri("https://example.test/security-events"),
                    SharedSecret = ValidSecret
                });
            },
            client =>
            {
                configuredHttpClient = true;
                client.DefaultRequestHeaders.Add("X-Test", "configured");
            });

        using var provider = services.BuildServiceProvider();
        var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient(AshlarSecurityEventWebhookSender.HttpClientName);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(provider.GetServices<ISecurityEventHandler>().Single(), Is.TypeOf<AshlarSecurityEventWebhookHandler>());
            Assert.That(provider.GetRequiredService<IAshlarSecurityEventWebhookSender>(), Is.TypeOf<AshlarSecurityEventWebhookSender>());
            Assert.That(provider.GetRequiredService<IAshlarSecurityEventWebhookEndpointTester>(), Is.TypeOf<AshlarSecurityEventWebhookEndpointTester>());
            Assert.That(provider.GetRequiredService<IAshlarSecurityEventWebhookDeliveryObserver>(), Is.TypeOf<NoOpAshlarSecurityEventWebhookDeliveryObserver>());
            Assert.That(provider.GetRequiredService<AshlarSecurityEventWebhookDeliveryFactory>(), Is.Not.Null);
            Assert.That(provider.GetService<IAshlarSecurityEventWebhookOutboxBrowser>(), Is.Null);
            Assert.That(provider.GetRequiredService<IOptions<AshlarSecurityEventWebhookOptions>>().Value.Endpoints.Single().Name, Is.EqualTo("audit"));
            Assert.That(configuredHttpClient, Is.True);
            Assert.That(httpClient.DefaultRequestHeaders.GetValues("X-Test").Single(), Is.EqualTo("configured"));
        }
    }

    [Test]
    public void AddAshlarSecurityEventWebhooksIsIdempotentForHandler()
    {
        var services = new ServiceCollection();

        services.AddAshlarSecurityEventWebhooks();
        services.AddAshlarSecurityEventWebhooks();

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetServices<ISecurityEventHandler>().OfType<AshlarSecurityEventWebhookHandler>(), Has.Exactly(1).Items);
            Assert.That(provider.GetServices<IAshlarSecurityEventWebhookSender>().OfType<AshlarSecurityEventWebhookSender>(), Has.Exactly(1).Items);
            Assert.That(provider.GetServices<IAshlarSecurityEventWebhookEndpointTester>().OfType<AshlarSecurityEventWebhookEndpointTester>(), Has.Exactly(1).Items);
            Assert.That(provider.GetServices<AshlarSecurityEventWebhookDeliveryFactory>(), Has.Exactly(1).Items);
        }
    }

    [Test]
    public async Task AddAshlarSecurityEventWebhooksWorksThroughFanOutSink()
    {
        var services = new ServiceCollection();
        var httpClientFactory = new TestHttpClientFactory();
        services.AddSingleton<IHttpClientFactory>(httpClientFactory);
        services.AddAshlarSecurityEventWebhooks();
        using var provider = services.BuildServiceProvider();

        var sink = provider.GetRequiredService<ISecurityEventSink>();

        await sink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "test.event",
            OccurredAt = DateTimeOffset.UtcNow
        });

        Assert.That(httpClientFactory.CreatedClients, Is.Empty);
    }

    [Test]
    public void AddAshlarSecurityEventWebhooksRejectsNullServices()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarWebhooksServiceCollectionExtensions.AddAshlarSecurityEventWebhooks(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("services"));
    }

    [Test]
    public void AddAshlarSecurityEventWebhooksValidatesOptionsOnStart()
    {
        var services = new ServiceCollection();
        services.AddAshlarSecurityEventWebhooks(options =>
        {
            options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
            {
                Name = "audit",
                Uri = new Uri("http://example.test/security-events")
            });
        });
        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());

        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(AshlarSecurityEventWebhookOptions)));
    }

    [Test]
    public void AddAshlarSecurityEventWebhooksPreservesHardenedHandlerWithSafeHttpClientConfiguration()
    {
        var services = new ServiceCollection();
        services.AddAshlarSecurityEventWebhooks(configureHttpClient: client =>
        {
            client.Timeout = TimeSpan.FromSeconds(12);
            client.DefaultRequestHeaders.Add("X-Test", "configured");
        });
        using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(AshlarSecurityEventWebhookSender.HttpClientName);
        var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient(AshlarSecurityEventWebhookSender.HttpClientName);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ContainsHardenedSocketsHandler(handler), Is.True);
            Assert.That(httpClient.Timeout, Is.EqualTo(TimeSpan.FromSeconds(12)));
            Assert.That(httpClient.DefaultRequestHeaders.GetValues("X-Test").Single(), Is.EqualTo("configured"));
        }
    }

    [Test]
    public void AddAshlarSecurityEventWebhookOutboxDoesNotSelfAttestDurableInfrastructure()
    {
        var services = new ServiceCollection();
        services.AddAshlarSecurityEventWebhookOutbox(options =>
        {
            options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
            {
                Name = "audit",
                Uri = new Uri("https://example.test/security-events"),
                SharedSecret = ValidSecret
            });
        });

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetServices<IDurableSecurityEventFanOutHandler>(), Is.Empty);
            Assert.That(provider.GetService<IAshlarSecurityEventWebhookEnqueuer>(), Is.Null);
            Assert.That(provider.GetServices<ISecurityEventHandler>(), Is.Empty);
            Assert.That(provider.GetRequiredService<AshlarSecurityEventWebhookDeliveryFactory>(), Is.Not.Null);
            Assert.That(provider.GetRequiredService<IAshlarSecurityEventWebhookDeliveryObserver>(), Is.TypeOf<NoOpAshlarSecurityEventWebhookDeliveryObserver>());
        }
    }

    [Test]
    public void AddAshlarSecurityEventWebhookOutboxRejectsNullServices()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarWebhooksServiceCollectionExtensions.AddAshlarSecurityEventWebhookOutbox(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("services"));
    }

    [Test]
    public void AddAshlarSecurityEventWebhookOutboxAllowsNullConfigure()
    {
        var services = new ServiceCollection();
        services.AddAshlarSecurityEventWebhookOutbox();

        using var provider = services.BuildServiceProvider();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetServices<IDurableSecurityEventFanOutHandler>(), Is.Empty);
            Assert.That(provider.GetServices<ISecurityEventHandler>(), Is.Empty);
        }
    }

    [Test]
    public void AddAshlarSecurityEventWebhookDeliveryObserverComposesWithExistingObserverAndSkipsNoOp()
    {
        var existingObserver = new RecordingDeliveryObserver();
        var services = new ServiceCollection();
        services.AddAshlarSecurityEventWebhooks();
        services.AddSingleton<IAshlarSecurityEventWebhookDeliveryObserver>(existingObserver);
        services.AddAshlarSecurityEventWebhookDeliveryObserver<RecordingDeliveryObserver>();
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IAshlarSecurityEventWebhookDeliveryObserver>().RecordDeliveryAttempt(CreateTelemetry());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<IAshlarSecurityEventWebhookDeliveryObserver>(), Is.TypeOf<CompositeAshlarSecurityEventWebhookDeliveryObserver>());
            Assert.That(provider.GetServices<IAshlarSecurityEventWebhookDeliveryObserverContribution>(), Has.Exactly(2).Items);
            Assert.That(existingObserver.Telemetry, Has.Count.EqualTo(1));
            Assert.That(provider.GetRequiredService<RecordingDeliveryObserver>().Telemetry, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public void AddAshlarSecurityEventWebhookDeliveryObserverComposesWithFactoryObserver()
    {
        var existingObserver = new RecordingDeliveryObserver();
        var services = new ServiceCollection();
        services.AddSingleton<IAshlarSecurityEventWebhookDeliveryObserver>(_ => existingObserver);
        services.AddAshlarSecurityEventWebhookDeliveryObserver<RecordingDeliveryObserver>();
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IAshlarSecurityEventWebhookDeliveryObserver>().RecordDeliveryAttempt(CreateTelemetry());

        Assert.That(existingObserver.Telemetry, Has.Count.EqualTo(1));
    }

    [Test]
    public void AddAshlarSecurityEventWebhookDeliveryObserverIsIdempotent()
    {
        var services = new ServiceCollection();
        services
            .AddAshlarSecurityEventWebhookDeliveryObserver<RecordingDeliveryObserver>()
            .AddAshlarSecurityEventWebhookDeliveryObserver<RecordingDeliveryObserver>();
        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetServices<IAshlarSecurityEventWebhookDeliveryObserver>(), Has.Exactly(1).Items);
            Assert.That(provider.GetServices<IAshlarSecurityEventWebhookDeliveryObserverContribution>(), Has.Exactly(1).Items);
            Assert.That(provider.GetServices<RecordingDeliveryObserver>(), Has.Exactly(1).Items);
        }
    }

    [Test]
    public void AddAshlarSecurityEventWebhookDeliveryObserverContinuesFanOutWhenObserverThrows()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAshlarSecurityEventWebhookDeliveryObserver, ThrowingDeliveryObserver>();
        services.AddAshlarSecurityEventWebhookDeliveryObserver<RecordingDeliveryObserver>();
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IAshlarSecurityEventWebhookDeliveryObserver>().RecordDeliveryAttempt(CreateTelemetry());

        Assert.That(provider.GetRequiredService<RecordingDeliveryObserver>().Telemetry, Has.Count.EqualTo(1));
    }

    [Test]
    public void WebhookCompositionsBuildWithStrictValidationWithoutHostedServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarProviderScoped(_ => Mock.Of<IUserRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<IUserAdministrationRepository>());
        services.AddSingleton(Mock.Of<ICredentialAdministrationRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationSessionRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionAdministrationRepository>());
        services.AddSingleton(Mock.Of<ISecurityEventAdministrationRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddPermissiveAccountSecurityGuard();
        services.AddPasswordHasher<PasswordHasherV1>();
        services.AddAshlarSecurityEventWebhooks(options =>
        {
            options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
            {
                Name = "best-effort",
                Uri = new Uri("https://example.test/security-events"),
                SharedSecret = ValidSecret
            });
        });
        services.AddAshlarSecurityEventWebhookOutbox(options =>
        {
            options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
            {
                Name = "outbox",
                Uri = new Uri("https://example.test/security-events/outbox"),
                SharedSecret = ValidSecret
            });
        });

        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(ISecurityEventSink),
            typeof(IAshlarSecurityEventWebhookSender),
            typeof(IAshlarSecurityEventWebhookEndpointTester),
            typeof(AshlarSecurityEventWebhookDeliveryFactory),
            typeof(IAshlarOperationsSummaryService));

        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetServices<ISecurityEventHandler>(), Has.Some.TypeOf<AshlarSecurityEventWebhookHandler>());
            Assert.That(scope.ServiceProvider.GetServices<IDurableSecurityEventFanOutHandler>(), Is.Empty);
            Assert.That(scope.ServiceProvider.GetServices<ISecurityEventHandler>(), Has.None.TypeOf<AshlarSecurityEventWebhookOutboxHandler>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarOperationsSummaryService>(), Is.TypeOf<AshlarOperationsSummaryService>());
            Assert.That(provider.GetServices<IHostedService>(), Is.Empty);
        }
    }

    private sealed class StubTransactionProvider : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class TestHttpClientFactory : IHttpClientFactory
    {
        public List<string> CreatedClients { get; } = [];

        public HttpClient CreateClient(string name)
        {
            CreatedClients.Add(name);
            return new HttpClient();
        }
    }

    private sealed class TestWebhookEnqueuer : IAshlarSecurityEventWebhookEnqueuer
    {
        public List<AshlarSecurityEventWebhookDelivery> Deliveries { get; } = [];

        public Task EnqueueAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken = default)
        {
            Deliveries.Add(delivery);
            return Task.CompletedTask;
        }
    }

    private static AshlarSecurityEventWebhookDeliveryTelemetry CreateTelemetry()
    {
        return new AshlarSecurityEventWebhookDeliveryTelemetry(
            AshlarSecurityEventWebhookDeliveryTelemetry.BestEffortDeliveryMode,
            "ashlar.sign_in.failed",
            "audit",
            AshlarSecurityEventWebhookDeliveryTelemetry.SuccessOutcome,
            null,
            TimeSpan.FromMilliseconds(12.5));
    }

    private sealed class RecordingDeliveryObserver : IAshlarSecurityEventWebhookDeliveryObserver
    {
        public List<AshlarSecurityEventWebhookDeliveryTelemetry> Telemetry { get; } = [];

        public void RecordDeliveryAttempt(AshlarSecurityEventWebhookDeliveryTelemetry telemetry)
        {
            Telemetry.Add(telemetry);
        }
    }

    private sealed class ThrowingDeliveryObserver : IAshlarSecurityEventWebhookDeliveryObserver
    {
        public void RecordDeliveryAttempt(AshlarSecurityEventWebhookDeliveryTelemetry telemetry)
        {
            throw new InvalidOperationException("observer failed");
        }
    }

    private sealed class RedirectServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);

        public RedirectServer()
        {
            _listener.Start();
            RedirectUri = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/redirect");
        }

        public Uri RedirectUri { get; }

        public int RequestCount { get; private set; }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            await ValueTask.CompletedTask;
        }

        public async Task ServeAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    using var client = await _listener.AcceptTcpClientAsync(cancellationToken);
                    RequestCount++;
                    await ReadRequestAsync(client.GetStream(), cancellationToken);
                    var response = RequestCount == 1
                        ? "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
        }

        private static async Task ReadRequestAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            var buffer = new byte[1024];
            var builder = new StringBuilder();
            do
            {
                var read = await stream.ReadAsync(buffer, cancellationToken);
                builder.Append(Encoding.ASCII.GetString(buffer, 0, read));
            }
            while (!builder.ToString().Contains("\r\n\r\n", StringComparison.Ordinal));
        }
    }

    private static bool ContainsHardenedSocketsHandler(HttpMessageHandler handler)
    {
        if (handler is SocketsHttpHandler socketsHandler)
        {
            return !socketsHandler.AllowAutoRedirect && socketsHandler.ConnectCallback != null;
        }

        if (handler is DelegatingHandler { InnerHandler: { } innerHandler })
        {
            return ContainsHardenedSocketsHandler(innerHandler);
        }

        var fields = handler.GetType().GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        foreach (var field in fields)
        {
            if (field.GetValue(handler) is HttpMessageHandler nestedHandler && ContainsHardenedSocketsHandler(nestedHandler))
            {
                return true;
            }
        }

        return false;
    }
}
