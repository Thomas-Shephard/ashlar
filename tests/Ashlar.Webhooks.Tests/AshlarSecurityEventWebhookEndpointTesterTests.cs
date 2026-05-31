using System.Net;
using System.Text;
using System.Text.Json;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.Options;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarSecurityEventWebhookEndpointTesterTests
{
    [Test]
    public async Task TestAsyncSendsOneSyntheticSafeSignedRequest()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        var tester = CreateTester(transport, CreateOptions(endpoint));

        var result = await tester.TestAsync("audit");

        var request = transport.Requests.Single();
        var json = request.ReadBody();
        var payload = JsonSerializer.Deserialize<JsonElement>(json);
        var headers = SingleValueHeaders(request.Headers);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.Sent));
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.FailureReason, Is.Empty);
            Assert.That(result.EventId, Is.EqualTo(payload.GetProperty("id").GetGuid()));
            Assert.That(request.Method, Is.EqualTo(HttpMethod.Post));
            Assert.That(request.RequestUri, Is.EqualTo(endpoint.Uri));
            Assert.That(request.ContentType, Is.EqualTo("application/json"));
            Assert.That(payload.GetProperty("eventType").GetString(), Is.EqualTo(AshlarSecurityEventWebhookEndpointTester.TestEventType));
            Assert.That(payload.GetProperty("occurredAt").GetDateTimeOffset(), Is.EqualTo(StaticNow));
            Assert.That(json, Does.Not.Contain("userId"));
            Assert.That(json, Does.Not.Contain("tenantId"));
            Assert.That(json, Does.Not.Contain("actorUserId"));
            Assert.That(json, Does.Not.Contain("sessionId"));
            Assert.That(json, Does.Not.Contain("providerType"));
            Assert.That(json, Does.Not.Contain("providerName"));
            Assert.That(json, Does.Not.Contain("correlationId"));
            Assert.That(json, Does.Not.Contain("metadata"));
            Assert.That(headers["X-Ashlar-Event-Type"], Is.EqualTo(AshlarSecurityEventWebhookEndpointTester.TestEventType));
            Assert.That(headers["X-Ashlar-Webhook-Endpoint"], Is.EqualTo("audit"));
            Assert.That(VerifySignature(request.Body, headers, "shared-secret", payload.GetProperty("id").GetGuid(), "audit", "/security-events").IsValid, Is.True);
        }
    }

    [Test]
    public async Task TestAsyncIgnoresEndpointEventFilters()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.EventTypes.Add("ashlar.sign_in.failed");
        var tester = CreateTester(transport, CreateOptions(endpoint));

        var result = await tester.TestAsync("audit");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.Sent));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task TestAsyncSupportsUnsignedEndpointOnlyWhenExplicitlyAllowed()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.SharedSecret = null;
        endpoint.AllowUnsigned = true;
        var tester = CreateTester(transport, CreateOptions(endpoint));

        var result = await tester.TestAsync("audit");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.Sent));
            Assert.That(transport.Requests.Single().Headers, Does.Not.ContainKey(AshlarSecurityEventWebhookSignature.SignatureHeaderName));
            Assert.That(transport.Requests.Single().Headers, Does.Not.ContainKey(AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName));
        }
    }

    [Test]
    public async Task TestAsyncReportsMissingSharedSecretWhenUnsignedNotAllowed()
    {
        var endpoint = CreateEndpoint();
        endpoint.SharedSecret = null;
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var tester = CreateTester(transport, CreateOptions(endpoint));

        var result = await tester.TestAsync("audit");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.MissingSharedSecret));
            Assert.That(result.FailureReason, Is.EqualTo("Webhook endpoint is missing a shared secret."));
            Assert.That(result.EventId, Is.Null);
            Assert.That(transport.Requests, Is.Empty);
        }
    }

    [Test]
    public async Task TestAsyncReportsMissingAndDisabledEndpointsWithoutSending()
    {
        var disabled = CreateEndpoint("disabled");
        disabled.Enabled = false;
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var tester = CreateTester(transport, CreateOptions(disabled));

        var missing = await tester.TestAsync("missing");
        var disabledResult = await tester.TestAsync("disabled");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.EndpointNotFound));
            Assert.That(missing.FailureReason, Is.EqualTo("Webhook endpoint was not found."));
            Assert.That(disabledResult.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.EndpointDisabled));
            Assert.That(disabledResult.FailureReason, Is.EqualTo("Webhook endpoint is disabled."));
            Assert.That(transport.Requests, Is.Empty);
        }
    }

    [Test]
    public async Task TestAsyncReportsDestinationRejected()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var tester = CreateTester(transport, CreateOptions(CreateEndpoint(uri: "https://127.0.0.1/security-events")));

        var result = await tester.TestAsync("audit");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.DestinationRejected));
            Assert.That(result.FailureReason, Is.EqualTo("Webhook destination was rejected."));
            Assert.That(result.EventId, Is.Not.Null);
            Assert.That(transport.Requests, Is.Empty);
        }
    }

    [Test]
    public async Task TestAsyncReportsNonSuccessAsDeliveryFailed()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.BadGateway);
        var tester = CreateTester(transport, CreateOptions(CreateEndpoint()));

        var result = await tester.TestAsync("audit");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed));
            Assert.That(result.FailureReason, Is.EqualTo("Webhook endpoint delivery failed."));
            Assert.That(result.EventId, Is.Not.Null);
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task TestAsyncReportsSenderExceptionAsDeliveryFailed()
    {
        var tester = CreateTester(
            new ThrowingHttpMessageHandler(new InvalidOperationException("transport failed")),
            CreateOptions(CreateEndpoint()));

        var result = await tester.TestAsync("audit");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed));
            Assert.That(result.EventId, Is.Not.Null);
        }
    }

    [Test]
    public async Task TestAsyncReportsTimeout()
    {
        var endpoint = CreateEndpoint();
        endpoint.Timeout = TimeSpan.FromMilliseconds(1);
        var tester = CreateTester(new TimeoutHttpMessageHandler(), CreateOptions(endpoint));

        var result = await tester.TestAsync("audit");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.TimedOut));
            Assert.That(result.FailureReason, Is.EqualTo("Webhook endpoint test timed out."));
            Assert.That(result.EventId, Is.Not.Null);
        }
    }

    [Test]
    public async Task TestAsyncReportsCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var tester = CreateTester(
            new CancelingHttpMessageHandler(cancellation),
            CreateOptions(CreateEndpoint()));

        var result = await tester.TestAsync("audit", cancellation.Token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.Canceled));
            Assert.That(result.FailureReason, Is.EqualTo("Webhook endpoint test was canceled."));
            Assert.That(result.EventId, Is.Not.Null);
        }
    }

    [Test]
    public void TestAsyncThrowsForPreCanceledTokenBeforePreparingRequest()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var tester = CreateTester(new RecordingHttpMessageHandler(HttpStatusCode.Accepted), CreateOptions(CreateEndpoint()));

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), () => tester.TestAsync("audit", cancellation.Token));
    }

    [Test]
    public async Task TestAsyncReportsCancellationBeforePayloadIsCreated()
    {
        using var cancellation = new CancellationTokenSource();
        var tester = CreateTester(
            new RecordingHttpMessageHandler(HttpStatusCode.Accepted),
            CreateOptions(CreateEndpoint()),
            new ThrowingTimeProvider(() =>
            {
                cancellation.Cancel();
                return new OperationCanceledException(cancellation.Token);
            }));

        var result = await tester.TestAsync("audit", cancellation.Token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.Canceled));
            Assert.That(result.EventId, Is.Null);
        }
    }

    [Test]
    public async Task TestAsyncReportsTimeoutBeforePayloadIsCreated()
    {
        var tester = CreateTester(
            new RecordingHttpMessageHandler(HttpStatusCode.Accepted),
            CreateOptions(CreateEndpoint()),
            new ThrowingTimeProvider(() => new OperationCanceledException()));

        var result = await tester.TestAsync("audit");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.TimedOut));
            Assert.That(result.EventId, Is.Null);
        }
    }

    [Test]
    public async Task TestAsyncReportsDeliveryFailedBeforePayloadIsCreated()
    {
        var tester = CreateTester(
            new RecordingHttpMessageHandler(HttpStatusCode.Accepted),
            CreateOptions(CreateEndpoint()),
            new ThrowingTimeProvider(() => new InvalidOperationException("time failed")));

        var result = await tester.TestAsync("audit");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed));
            Assert.That(result.EventId, Is.Null);
        }
    }

    [Test]
    public void ConstructorAndTestAsyncValidateArguments()
    {
        var sender = CreateSender(new RecordingHttpMessageHandler(HttpStatusCode.Accepted));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookEndpointTester(null!, sender))?.ParamName, Is.EqualTo("options"));
            Assert.That(Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookEndpointTester(Options.Create(CreateOptions()), null!))?.ParamName, Is.EqualTo("sender"));
            Assert.That(Assert.ThrowsAsync<ArgumentException>(() => new AshlarSecurityEventWebhookEndpointTester(Options.Create(CreateOptions()), sender).TestAsync(" "))?.ParamName, Is.EqualTo("endpointName"));
        }
    }

    [Test]
    public async Task TestAsyncReportsMissingUriAsDeliveryFailed()
    {
        var endpoint = CreateEndpoint();
        endpoint.Uri = null;
        var tester = CreateTester(new RecordingHttpMessageHandler(HttpStatusCode.Accepted), CreateOptions(endpoint));

        var result = await tester.TestAsync("audit");

        Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed));
    }

    [Test]
    public void ResultFailureReasonsAreSafe()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(new AshlarSecurityEventWebhookEndpointTestResult(AshlarSecurityEventWebhookEndpointTestStatus.Sent).FailureReason, Is.Empty);
            Assert.That(new AshlarSecurityEventWebhookEndpointTestResult(AshlarSecurityEventWebhookEndpointTestStatus.DestinationRejected).FailureReason, Is.EqualTo("Webhook destination was rejected."));
            Assert.That(new AshlarSecurityEventWebhookEndpointTestResult(AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed).FailureReason, Is.EqualTo("Webhook endpoint delivery failed."));
            Assert.That(new AshlarSecurityEventWebhookEndpointTestResult(AshlarSecurityEventWebhookEndpointTestStatus.TimedOut).FailureReason, Is.EqualTo("Webhook endpoint test timed out."));
            Assert.That(new AshlarSecurityEventWebhookEndpointTestResult(AshlarSecurityEventWebhookEndpointTestStatus.Canceled).FailureReason, Is.EqualTo("Webhook endpoint test was canceled."));
            Assert.That(new AshlarSecurityEventWebhookEndpointTestResult((AshlarSecurityEventWebhookEndpointTestStatus)99).FailureReason, Is.EqualTo("Webhook endpoint delivery failed."));
        }
    }

    [Test]
    public void MapStatusDefaultsUnknownSenderOutcomeToDeliveryFailed()
    {
        var result = AshlarSecurityEventWebhookEndpointTester.MapStatus((AshlarSecurityEventWebhookSendResult)99);

        Assert.That(result, Is.EqualTo(AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed));
    }

    [Test]
    public async Task SendAsyncMapsSenderOutcomes()
    {
        var accepted = await CreateSender(new RecordingHttpMessageHandler(HttpStatusCode.Accepted)).SendAsync(CreateDelivery());
        var failed = await CreateSender(new RecordingHttpMessageHandler(HttpStatusCode.BadGateway)).SendAsync(CreateDelivery());
        var rejected = await CreateSender(new RecordingHttpMessageHandler(HttpStatusCode.Accepted)).SendAsync(
            CreateDelivery(new Uri("https://127.0.0.1/security-events")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(accepted, Is.EqualTo(AshlarSecurityEventWebhookSendResult.Sent));
            Assert.That(failed, Is.EqualTo(AshlarSecurityEventWebhookSendResult.DeliveryFailed));
            Assert.That(rejected, Is.EqualTo(AshlarSecurityEventWebhookSendResult.DestinationRejected));
        }
    }

    private static readonly DateTimeOffset StaticNow = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    private static AshlarSecurityEventWebhookEndpointTester CreateTester(
        HttpMessageHandler transport,
        AshlarSecurityEventWebhookOptions options,
        TimeProvider? timeProvider = null)
    {
        return new AshlarSecurityEventWebhookEndpointTester(
            Options.Create(options),
            CreateSender(transport),
            timeProvider ?? new StaticTimeProvider(StaticNow));
    }

    private static AshlarSecurityEventWebhookSender CreateSender(HttpMessageHandler transport)
    {
        return new AshlarSecurityEventWebhookSender(
            new TestHttpClientFactory(transport),
            destinationValidator: new AshlarSecurityEventWebhookDestinationValidator(
                new StaticDestinationResolver(),
                Options.Create(new AshlarSecurityEventWebhookOptions())));
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
            Uri = new Uri(uri),
            SharedSecret = "shared-secret"
        };
    }

    private static AshlarSecurityEventWebhookDelivery CreateDelivery(Uri? uri = null)
    {
        var payload = new AshlarSecurityEventWebhookPayload
        {
            Id = Guid.NewGuid(),
            EventType = "ashlar.webhook.test",
            OccurredAt = StaticNow
        };
        var body = AshlarSecurityEventWebhookPayloadSerializer.Serialize(payload);
        var endpoint = CreateEndpoint(uri: (uri ?? new Uri("https://example.test/security-events")).ToString());
        return new AshlarSecurityEventWebhookDelivery(
            endpoint.Name,
            endpoint.Uri!,
            TimeSpan.FromSeconds(10),
            AshlarSecurityEventWebhookDeliveryFactory.CreateHeaders(endpoint, payload, body, StaticNow),
            payload,
            body);
    }

    private static Dictionary<string, string> SingleValueHeaders(IReadOnlyDictionary<string, string[]> headers)
    {
        return headers.ToDictionary(header => header.Key, header => header.Value.Single(), StringComparer.Ordinal);
    }

    private static AshlarSecurityEventWebhookVerificationResult VerifySignature(
        ReadOnlySpan<byte> body,
        IReadOnlyDictionary<string, string> headers,
        string sharedSecret,
        Guid eventId,
        string endpointName,
        string destinationPathAndQuery)
    {
        return AshlarSecurityEventWebhookSignature.Verify(new AshlarSecurityEventWebhookVerificationRequest
        {
            Body = body.ToArray(),
            Headers = headers,
            SharedSecret = sharedSecret,
            EventId = eventId,
            EndpointName = endpointName,
            DestinationPathAndQuery = destinationPathAndQuery,
            TimeProvider = new StaticTimeProvider(StaticNow)
        });
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler transport) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            Assert.That(name, Is.EqualTo(AshlarSecurityEventWebhookSender.HttpClientName));
            return new HttpClient(transport, disposeHandler: false);
        }
    }

    private sealed class StaticDestinationResolver : IAshlarSecurityEventWebhookDestinationResolver
    {
        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<IPAddress> addresses = [IPAddress.Parse("93.184.216.34")];
            return ValueTask.FromResult(addresses);
        }
    }

    private sealed class StaticTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }

    private sealed class ThrowingTimeProvider(Func<Exception> exceptionFactory) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            throw exceptionFactory();
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

    private sealed class ThrowingHttpMessageHandler(Exception exception) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw exception;
        }
    }

    private sealed class CancelingHttpMessageHandler(CancellationTokenSource cancellation) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellation.Cancel();
            throw new OperationCanceledException(cancellation.Token);
        }
    }

    private sealed class TimeoutHttpMessageHandler : HttpMessageHandler
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
}
