using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Authentication;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarSecurityEventWebhookHandlerTests
{
    [Test]
    public async Task HandleAsyncPostsSafeJsonPayload()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var handler = CreateHandler(transport, CreateOptions(CreateEndpoint()));
        var securityEvent = CreateEvent();

        await handler.HandleAsync(securityEvent);

        var request = transport.Requests.Single();
        var json = request.ReadBody();
        var payload = JsonSerializer.Deserialize<JsonElement>(json);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Method, Is.EqualTo(HttpMethod.Post));
            Assert.That(request.RequestUri, Is.EqualTo(new Uri("https://example.test/security-events")));
            Assert.That(request.ContentType, Is.EqualTo("application/json"));
            Assert.That(payload.GetProperty("id").GetGuid(), Is.EqualTo(securityEvent.Id));
            Assert.That(payload.GetProperty("eventType").GetString(), Is.EqualTo(securityEvent.EventType));
            Assert.That(payload.GetProperty("occurredAt").GetDateTimeOffset(), Is.EqualTo(securityEvent.OccurredAt));
            Assert.That(payload.GetProperty("outcome").GetString(), Is.EqualTo(securityEvent.Outcome));
            Assert.That(payload.GetProperty("failureReason").GetString(), Is.EqualTo(securityEvent.FailureReason));
            Assert.That(payload.GetProperty("userId").GetGuid(), Is.EqualTo(securityEvent.UserId));
            Assert.That(payload.GetProperty("tenantId").GetGuid(), Is.EqualTo(securityEvent.TenantId));
            Assert.That(payload.GetProperty("actorUserId").GetGuid(), Is.EqualTo(securityEvent.ActorUserId));
            Assert.That(payload.GetProperty("sessionId").GetGuid(), Is.EqualTo(securityEvent.SessionId));
            Assert.That(payload.GetProperty("providerType").GetString(), Is.EqualTo(ProviderType.Oidc.Value));
            Assert.That(payload.GetProperty("providerName").GetString(), Is.EqualTo("Contoso"));
            Assert.That(payload.GetProperty("correlationId").GetString(), Is.EqualTo(securityEvent.CorrelationId));
        }
    }

    [Test]
    public async Task HandleAsyncDoesNotSerializeUnsafeFields()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var handler = CreateHandler(transport, CreateOptions(CreateEndpoint()));

        await handler.HandleAsync(CreateEvent());

        var json = transport.Requests.Single().ReadBody();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(json, Does.Not.Contain("ipAddress"));
            Assert.That(json, Does.Not.Contain("userAgent"));
            Assert.That(json, Does.Not.Contain("properties"));
            Assert.That(json, Does.Not.Contain("token_hash"));
            Assert.That(json, Does.Not.Contain("secret-token-hash"));
        }
    }

    [Test]
    public async Task HandleAsyncAddsHeadersAndSignature()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.SharedSecret = "shared-secret";
        var handler = CreateHandler(transport, CreateOptions(endpoint));
        var securityEvent = CreateEvent();

        await handler.HandleAsync(securityEvent);

        var request = transport.Requests.Single();
        var body = Encoding.UTF8.GetBytes(request.ReadBody());
        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Headers["X-Ashlar-Event-Id"].Single(), Is.EqualTo(securityEvent.Id.ToString("D")));
            Assert.That(request.Headers["X-Ashlar-Event-Type"].Single(), Is.EqualTo(securityEvent.EventType));
            Assert.That(request.Headers["X-Ashlar-Webhook-Endpoint"].Single(), Is.EqualTo(endpoint.Name));
            Assert.That(request.Headers["X-Ashlar-Timestamp"].Single(), Is.EqualTo(securityEvent.OccurredAt.ToString("O")));
            Assert.That(request.Headers[AshlarSecurityEventWebhookSender.SignatureHeaderName].Single(), Is.EqualTo(AshlarSecurityEventWebhookSender.CreateSignature("shared-secret", body)));
        }
    }

    [Test]
    public void CreateSignatureReturnsKnownHmacSha256Value()
    {
        var signature = AshlarSecurityEventWebhookSender.CreateSignature("secret", "hello"u8);

        Assert.That(signature, Is.EqualTo("sha256=88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"));
    }

    [Test]
    public async Task HandleAsyncSkipsDisabledEndpoints()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.Enabled = false;
        var handler = CreateHandler(transport, CreateOptions(endpoint));

        await handler.HandleAsync(CreateEvent());

        Assert.That(transport.Requests, Is.Empty);
    }

    [Test]
    public async Task HandleAsyncAppliesEventTypeAllowList()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.EventTypes.Add("different.event");
        var handler = CreateHandler(transport, CreateOptions(endpoint));

        await handler.HandleAsync(CreateEvent());

        Assert.That(transport.Requests, Is.Empty);
    }

    [Test]
    public async Task HandleAsyncSendsWhenEventTypeAllowListMatches()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.EventTypes.Add("ASHLAR.SIGN_IN.FAILED");
        var handler = CreateHandler(transport, CreateOptions(endpoint));

        await handler.HandleAsync(CreateEvent());

        Assert.That(transport.Requests, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task HandleAsyncSendsEligibleEndpointsConcurrently()
    {
        var transport = new ConcurrentHttpMessageHandler();
        var first = CreateEndpoint("first", "https://first.example.test/security-events");
        var second = CreateEndpoint("second", "https://second.example.test/security-events");
        var handler = CreateHandler(transport, CreateOptions(first, second));

        var delivery = handler.HandleAsync(CreateEvent());
        var bothStarted = await WaitForAsync(transport.BothStarted);
        transport.Release();
        await delivery;

        Assert.That(bothStarted, Is.True);
    }

    [Test]
    public void DeliveryFactorySerializesPayloadOnceForEligibleEndpoints()
    {
        var first = CreateEndpoint("first", "https://first.example.test/security-events");
        var second = CreateEndpoint("second", "https://second.example.test/security-events");
        var factory = new AshlarSecurityEventWebhookDeliveryFactory(Options.Create(CreateOptions(first, second)));

        var deliveries = factory.CreateDeliveries(CreateEvent());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(deliveries, Has.Count.EqualTo(2));
            Assert.That(MemoryMarshal.TryGetArray(deliveries[0].Body, out var firstBody), Is.True);
            Assert.That(MemoryMarshal.TryGetArray(deliveries[1].Body, out var secondBody), Is.True);
            Assert.That(firstBody.Array, Is.SameAs(secondBody.Array));
        }
    }

    [Test]
    public async Task HandleAsyncContinuesAfterEndpointFailure()
    {
        var logger = new TestLogger<AshlarSecurityEventWebhookHandler>();
        var transport = new RoutingHttpMessageHandler(request =>
            string.Equals(request.RequestUri?.Host, "first.example.test", StringComparison.Ordinal)
                ? throw new HttpRequestException("transport failed")
                : new HttpResponseMessage(HttpStatusCode.Accepted));
        var first = CreateEndpoint("first", "https://first.example.test/security-events");
        var second = CreateEndpoint("second", "https://second.example.test/security-events");
        var handler = CreateHandler(transport, CreateOptions(first, second), logger);

        await handler.HandleAsync(CreateEvent());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Has.Count.EqualTo(2));
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Message, Does.Contain("Endpoint=first"));
            Assert.That(logger.Entries[0].Message, Does.Contain("EventType=ashlar.sign_in.failed"));
            Assert.That(logger.Entries[0].Exception, Is.TypeOf<HttpRequestException>());
        }
    }

    [Test]
    public async Task HandleAsyncLogsNonSuccessStatusWithoutThrowing()
    {
        var logger = new TestLogger<AshlarSecurityEventWebhookSender>();
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.BadGateway);
        var sender = new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(transport), logger);

        await sender.SendAsync(CreateDelivery());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Message, Does.Contain("StatusCode=502"));
            Assert.That(logger.Entries[0].Exception, Is.Null);
        }
    }

    [Test]
    public void HandleAsyncRespectsCallerCancellation()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var handler = CreateHandler(transport, CreateOptions(CreateEndpoint()));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), async () => await handler.HandleAsync(CreateEvent(), cancellation.Token));
        Assert.That(transport.Requests, Is.Empty);
    }

    [Test]
    public void HandleAsyncRethrowsCallerCancellationFromHttp()
    {
        using var cancellation = new CancellationTokenSource();
        var transport = new QueueingHttpMessageHandler(_ =>
        {
            cancellation.Cancel();
            throw new OperationCanceledException(cancellation.Token);
        });
        var handler = CreateHandler(transport, CreateOptions(CreateEndpoint()));

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), async () => await handler.HandleAsync(CreateEvent(), cancellation.Token));
    }

    [Test]
    public void HandleAsyncLogsEndpointTimeoutCancellationAsFailure()
    {
        var logger = new TestLogger<AshlarSecurityEventWebhookHandler>();
        var transport = new QueueingHttpMessageHandler(_ => throw new OperationCanceledException());
        var endpoint = CreateEndpoint();
        endpoint.Timeout = TimeSpan.FromSeconds(1);
        var handler = CreateHandler(transport, CreateOptions(endpoint), logger);

        Assert.DoesNotThrowAsync(async () => await handler.HandleAsync(CreateEvent()));
        Assert.That(logger.Entries.Single().Exception, Is.TypeOf<OperationCanceledException>());
    }

    [Test]
    public void HandleAsyncUsesDefaultEndpointTimeout()
    {
        var logger = new TestLogger<AshlarSecurityEventWebhookHandler>();
        var transport = new TimeoutObservingHttpMessageHandler();
        var options = CreateOptions(CreateEndpoint());
        options.Timeout = TimeSpan.FromMilliseconds(1);
        var handler = CreateHandler(transport, options, logger);

        Assert.DoesNotThrowAsync(async () => await handler.HandleAsync(CreateEvent()));

        Assert.That(logger.Entries.Single().Exception, Is.InstanceOf<OperationCanceledException>());
    }

    [Test]
    public void HandleAsyncThrowsForNullEvent()
    {
        var handler = CreateHandler(new RecordingHttpMessageHandler(HttpStatusCode.Accepted), CreateOptions(CreateEndpoint()));

        var exception = Assert.ThrowsAsync<ArgumentNullException>(async () => await handler.HandleAsync(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("securityEvent"));
    }

    [Test]
    public void ConstructorThrowsForNullHttpClientFactory()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookHandler(null!, new TestWebhookSender()));

        Assert.That(exception?.ParamName, Is.EqualTo("deliveryFactory"));
    }

    [Test]
    public void ConstructorThrowsForNullOptions()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookHandler(new AshlarSecurityEventWebhookDeliveryFactory(Options.Create(new AshlarSecurityEventWebhookOptions())), null!));

        Assert.That(exception?.ParamName, Is.EqualTo("sender"));
    }

    [Test]
    public void CreatePayloadThrowsForNullEvent()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookDeliveryFactory.CreatePayload(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("securityEvent"));
    }

    [Test]
    public void CreateSignatureThrowsForNullSecret()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookSender.CreateSignature(null!, []));

        Assert.That(exception?.ParamName, Is.EqualTo("sharedSecret"));
    }

    private static async Task<bool> WaitForAsync(Task task)
    {
        var completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5)));
        return completed == task;
    }

    private static AshlarSecurityEventWebhookHandler CreateHandler(
        HttpMessageHandler transport,
        AshlarSecurityEventWebhookOptions options,
        TestLogger<AshlarSecurityEventWebhookHandler>? logger = null)
    {
        return new AshlarSecurityEventWebhookHandler(
            new AshlarSecurityEventWebhookDeliveryFactory(Options.Create(options)),
            new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(transport)),
            logger);
    }

    private static AshlarSecurityEventWebhookOptions CreateOptions(params AshlarSecurityEventWebhookEndpointOptions[] endpoints)
    {
        var options = new AshlarSecurityEventWebhookOptions();
        foreach (var endpoint in endpoints)
        {
            options.Endpoints.Add(endpoint);
        }

        return options;
    }

    private static AshlarSecurityEventWebhookEndpointOptions CreateEndpoint(
        string name = "audit",
        string uri = "https://example.test/security-events")
    {
        return new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = name,
            Uri = new Uri(uri)
        };
    }

    private static AshlarSecurityEventWebhookDelivery CreateDelivery()
    {
        return new AshlarSecurityEventWebhookDelivery(
            "audit",
            new Uri("https://example.test/security-events"),
            TimeSpan.FromSeconds(10),
            null,
            CreatePayload());
    }

    private static AshlarSecurityEventWebhookPayload CreatePayload()
    {
        return AshlarSecurityEventWebhookDeliveryFactory.CreatePayload(CreateEvent());
    }

    private static AshlarSecurityEventWebhookPayload CreatePayload(string eventType)
    {
        return new AshlarSecurityEventWebhookPayload
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            OccurredAt = DateTimeOffset.UtcNow
        };
    }

    private static AshlarSecurityEvent CreateEvent()
    {
        return new AshlarSecurityEvent
        {
            Id = new Guid("11111111-1111-1111-1111-111111111111"),
            EventType = "ashlar.sign_in.failed",
            OccurredAt = new DateTimeOffset(2026, 5, 24, 12, 0, 0, TimeSpan.Zero),
            UserId = new Guid("22222222-2222-2222-2222-222222222222"),
            TenantId = new Guid("33333333-3333-3333-3333-333333333333"),
            ActorUserId = new Guid("44444444-4444-4444-4444-444444444444"),
            SessionId = new Guid("55555555-5555-5555-5555-555555555555"),
            Provider = new AuthenticationProviderKey(ProviderType.Oidc, "Contoso"),
            IpAddress = "203.0.113.10",
            UserAgent = "Sensitive Browser",
            CorrelationId = "correlation-1",
            Outcome = SecurityEventOutcomes.Failure,
            FailureReason = "invalid_code",
            Properties = new Dictionary<string, string> { ["token_hash"] = "secret-token-hash" }
        };
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler transport) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            Assert.That(name, Is.EqualTo(AshlarSecurityEventWebhookSender.HttpClientName));
            return new HttpClient(transport, disposeHandler: false);
        }
    }

    [Test]
    public void DeliveryFactoryThrowsForNullOptions()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookDeliveryFactory(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("options"));
    }

    [Test]
    public void SenderThrowsForNullHttpClientFactory()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookSender(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("httpClientFactory"));
    }

    [Test]
    public void SenderThrowsForNullDelivery()
    {
        var sender = new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.Accepted)));

        var exception = Assert.ThrowsAsync<ArgumentNullException>(async () => await sender.SendAsync(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("delivery"));
    }

    [Test]
    public void DeliveryThrowsForInvalidArguments()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery(" ", new Uri("https://example.test"), TimeSpan.FromSeconds(1), null, CreatePayload()))?.ParamName, Is.EqualTo("endpointName"));
            Assert.That(Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookDelivery("audit", null!, TimeSpan.FromSeconds(1), null, CreatePayload()))?.ParamName, Is.EqualTo("uri"));
            Assert.That(Assert.Throws<ArgumentOutOfRangeException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.Zero, null, CreatePayload()))?.ParamName, Is.EqualTo("timeout"));
            Assert.That(Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), null, null!))?.ParamName, Is.EqualTo("payload"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), " ", CreatePayload()))?.ParamName, Is.EqualTo("sharedSecret"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit\r\nbad", new Uri("https://example.test"), TimeSpan.FromSeconds(1), null, CreatePayload()))?.ParamName, Is.EqualTo("endpointName"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), null, CreatePayload(" ")))?.ParamName, Is.EqualTo("payload.EventType"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), null, CreatePayload("bad\r\nevent")))?.ParamName, Is.EqualTo("payload.EventType"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), null, CreatePayload(), ReadOnlyMemory<byte>.Empty))?.ParamName, Is.EqualTo("body"));
        }
    }

    [Test]
    public void DeliveryFactoryThrowsWhenActiveEndpointHasNoUri()
    {
        var endpoint = CreateEndpoint();
        endpoint.Uri = null;
        var factory = new AshlarSecurityEventWebhookDeliveryFactory(Options.Create(CreateOptions(endpoint)));

        var exception = Assert.Throws<InvalidOperationException>(() => factory.CreateDeliveries(CreateEvent()));

        Assert.That(exception?.Message, Is.EqualTo("Active webhook endpoint is missing a URI."));
    }

    [Test]
    public void CreatePayloadAllowsMissingProvider()
    {
        var securityEvent = CreateEvent() with { Provider = null };

        var payload = AshlarSecurityEventWebhookDeliveryFactory.CreatePayload(securityEvent);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(payload.ProviderType, Is.Null);
            Assert.That(payload.ProviderName, Is.Null);
        }
    }

    [Test]
    public void SerializePayloadThrowsForNullPayload()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookPayloadSerializer.Serialize(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("payload"));
    }

    [Test]
    public void HeaderValueSafetyRejectsNullValue()
    {
        Assert.That(AshlarSecurityEventWebhookHeaderValues.IsSafe(null), Is.False);
    }

    private sealed class TestWebhookSender : IAshlarSecurityEventWebhookSender
    {
        public Task SendAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingHttpMessageHandler(HttpStatusCode statusCode) : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(await RecordedRequest.CreateAsync(request, cancellationToken));
            return new HttpResponseMessage(statusCode);
        }
    }

    private sealed class QueueingHttpMessageHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] responses) : HttpMessageHandler
    {
        private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses = new(responses);

        public List<RecordedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(await RecordedRequest.CreateAsync(request, cancellationToken));
            return _responses.Dequeue()(request);
        }
    }

    private sealed class RoutingHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(await RecordedRequest.CreateAsync(request, cancellationToken));
            return response(request);
        }
    }

    private sealed class ConcurrentHttpMessageHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _bothStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _started;

        public Task BothStarted => _bothStarted.Task;

        public void Release()
        {
            _release.SetResult();
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _started) == 2)
            {
                _bothStarted.SetResult();
            }

            await _release.Task.WaitAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }

    private sealed class TimeoutObservingHttpMessageHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }

    private sealed record RecordedRequest(
        HttpMethod Method,
        Uri? RequestUri,
        string? ContentType,
        IReadOnlyDictionary<string, string[]> Headers,
        byte[] Body)
    {
        public static async Task<RecordedRequest> CreateAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var headers = request.Headers.ToDictionary(header => header.Key, header => header.Value.ToArray(), StringComparer.Ordinal);
            var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            return new RecordedRequest(
                request.Method,
                request.RequestUri,
                request.Content?.Headers.ContentType?.MediaType,
                headers,
                body);
        }

        public string ReadBody()
        {
            return Encoding.UTF8.GetString(Body);
        }
    }

    private sealed class TestLogger<T> : ILogger<T>
    {
        public List<LogEntry> Entries { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add(new LogEntry(logLevel, formatter(state, exception), exception));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }

    private sealed record LogEntry(LogLevel Level, string Message, Exception? Exception);
}
