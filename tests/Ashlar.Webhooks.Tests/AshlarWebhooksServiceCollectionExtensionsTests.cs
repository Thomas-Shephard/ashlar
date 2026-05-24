using Ashlar.Auditing;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarWebhooksServiceCollectionExtensionsTests
{
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
                    Uri = new Uri("https://example.test/security-events")
                });
            },
            builder =>
            {
                configuredHttpClient = true;
                builder.ConfigureHttpClient(client =>
                {
                    client.DefaultRequestHeaders.Add("X-Test", "configured");
                });
            });

        using var provider = services.BuildServiceProvider();
        var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient(AshlarSecurityEventWebhookHandler.HttpClientName);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(provider.GetServices<ISecurityEventHandler>().Single(), Is.TypeOf<AshlarSecurityEventWebhookHandler>());
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

        Assert.That(provider.GetServices<ISecurityEventHandler>().OfType<AshlarSecurityEventWebhookHandler>(), Has.Exactly(1).Items);
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

    private sealed class TestHttpClientFactory : IHttpClientFactory
    {
        public List<string> CreatedClients { get; } = [];

        public HttpClient CreateClient(string name)
        {
            CreatedClients.Add(name);
            return new HttpClient();
        }
    }
}
