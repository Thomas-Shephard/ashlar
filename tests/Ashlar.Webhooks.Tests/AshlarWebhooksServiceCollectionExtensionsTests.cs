using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Operational.Diagnostics;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Testing.DependencyInjection;
using Ashlar.Testing;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarWebhooksServiceCollectionExtensionsTests
{
    private const string ValidSecret = "0123456789abcdef0123456789abcdef";
    private static readonly AccountSecurityActorTestContext Security = new(DateTimeOffset.UtcNow, IAccountSecurityAdministrationService.ProofPurpose);
    [Test]
    public void AddAshlarSecurityEventWebhooksRegistersHandlerAndOptions()
    {
        var services = new ServiceCollection();
        AddOperationalSecurity(services);
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
        var transport = provider.GetRequiredService<AshlarSecurityEventWebhookTransport>();

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
            Assert.That(transport, Is.Not.Null);
        }
    }

    [Test]
    public void AddAshlarSecurityEventWebhooksIsIdempotentForHandler()
    {
        var services = new ServiceCollection();
        AddOperationalSecurity(services);

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
    public async Task AddAshlarSecurityEventWebhooksIgnoresCallerOwnedHttpClientFactory()
    {
        var server = ConnectionServer.TryCreate();
        if (server is null)
        {
            Assert.Ignore("This socket integration test requires a policy-allowed local network address.");
            return;
        }

        await using var ownedServer = server;
        var services = new ServiceCollection();
        var httpClientFactory = new TestHttpClientFactory();
        services.AddSingleton<IHttpClientFactory>(httpClientFactory);
        services.AddSingleton<IAshlarSecurityEventWebhookDestinationResolver>(new StaticDestinationResolver(server.Address));
        services.AddAshlarSecurityEventWebhooks(options =>
        {
            options.DestinationPolicy = AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks;
            options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
            {
                Name = "audit",
                Uri = server.Uri,
                SharedSecret = ValidSecret
            });
        });
        using var provider = services.BuildServiceProvider();

        var sink = provider.GetRequiredService<ISecurityEventSink>();
        var senderConstructor = typeof(AshlarSecurityEventWebhookSender).GetConstructors().Single();

        var delivery = sink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = "ashlar.sign_in.failed",
            OccurredAt = DateTimeOffset.UtcNow,
            Outcome = SecurityEventOutcomes.Failure
        });
        await server.AcceptAndCloseAsync();
        await delivery;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(typeof(AshlarSecurityEventWebhookSender).IsNotPublic, Is.True);
            Assert.That(senderConstructor.GetParameters()[0].ParameterType, Is.EqualTo(typeof(AshlarSecurityEventWebhookTransport)));
            Assert.That(senderConstructor.GetParameters(), Has.None.Property("ParameterType").EqualTo(typeof(IHttpClientFactory)));
            Assert.That(ContainsHardenedSocketsHandler(provider.GetRequiredService<AshlarSecurityEventWebhookTransport>()), Is.True);
            Assert.That(httpClientFactory.CreatedClients, Is.Empty);
            Assert.That(server.ConnectionCount, Is.EqualTo(1));
        }
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
        var transport = provider.GetRequiredService<AshlarSecurityEventWebhookTransport>();
        var httpClient = GetTransportHttpClient(transport);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ContainsHardenedSocketsHandler(transport), Is.True);
            Assert.That(httpClient.Timeout, Is.EqualTo(TimeSpan.FromSeconds(12)));
            Assert.That(httpClient.DefaultRequestHeaders.GetValues("X-Test").Single(), Is.EqualTo("configured"));
            Assert.That(provider.GetRequiredService<IAshlarSecurityEventWebhookSender>(), Is.TypeOf<AshlarSecurityEventWebhookSender>());
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
    public void AddAshlarSecurityEventWebhookOutboxAggregatesSafeClientConfigurationAcrossRegistrations()
    {
        var configured = new List<string>();
        var services = new ServiceCollection();
        services.AddAshlarSecurityEventWebhookOutbox(configureHttpClient: _ => configured.Add("first"));
        services.AddAshlarSecurityEventWebhookOutbox();
        services.AddAshlarSecurityEventWebhookOutbox(configureHttpClient: _ => configured.Add("second"));

        using var provider = services.BuildServiceProvider();
        _ = provider.GetRequiredService<AshlarSecurityEventWebhookTransport>();

        Assert.That(string.Join(",", configured), Is.EqualTo("first,second"));
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
        AddOperationalSecurity(services);
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

    private static void AddOperationalSecurity(IServiceCollection services)
    {
        services.AddSingleton<IAuthenticationSessionRepository>(Security.Sessions);
        services.AddSingleton<IAccountSecurityOperationAuthorizer>(Security.Authorizer);
        services.AddSingleton<IPersistentSecurityEventSink>(Security.AuditSink);
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

    private sealed class ConnectionServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;

        private ConnectionServer(IPAddress address)
        {
            Address = address;
            _listener = new TcpListener(Address, 0);
            _listener.Start();
            Uri = new Uri($"https://example.test:{((IPEndPoint)_listener.LocalEndpoint).Port}/");
        }

        public static ConnectionServer? TryCreate()
        {
            foreach (var address in NetworkInterface.GetAllNetworkInterfaces()
                         .Where(network => network.OperationalStatus == OperationalStatus.Up)
                         .SelectMany(network => network.GetIPProperties().UnicastAddresses)
                         .Select(unicast => unicast.Address)
                         .Where(address => !AshlarSecurityEventWebhookDestinationValidator.IsBlockedAddress(
                             address,
                             AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks)))
            {
                try
                {
                    return new ConnectionServer(address);
                }
                catch (SocketException)
                {
                }
            }

            return null;
        }

        public IPAddress Address { get; }

        public Uri Uri { get; }

        public int ConnectionCount { get; private set; }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            await ValueTask.CompletedTask;
        }

        public async Task AcceptAndCloseAsync()
        {
            using var client = await _listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
            ConnectionCount++;
        }
    }

    private sealed class StaticDestinationResolver(IPAddress address) : IAshlarSecurityEventWebhookDestinationResolver
    {
        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<IPAddress> addresses = [address];
            return ValueTask.FromResult(addresses);
        }
    }

    private static HttpClient GetTransportHttpClient(AshlarSecurityEventWebhookTransport transport)
    {
        return (HttpClient)typeof(AshlarSecurityEventWebhookTransport)
            .GetField("_httpClient", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(transport)!;
    }

    private static bool ContainsHardenedSocketsHandler(object value)
    {
        if (value is SocketsHttpHandler socketsHandler)
        {
            return !socketsHandler.AllowAutoRedirect && !socketsHandler.UseProxy && socketsHandler.ConnectCallback != null;
        }

        if (value is DelegatingHandler { InnerHandler: { } innerHandler })
        {
            return ContainsHardenedSocketsHandler(innerHandler);
        }

        for (var type = value.GetType(); type != null; type = type.BaseType)
        {
            foreach (var field in type.GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic))
            {
                if (field.GetValue(value) is { } nested
                    && (nested is HttpMessageHandler || nested is HttpMessageInvoker)
                    && ContainsHardenedSocketsHandler(nested))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
