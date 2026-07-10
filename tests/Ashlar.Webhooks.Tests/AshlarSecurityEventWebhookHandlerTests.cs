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
    private static readonly IReadOnlyDictionary<string, string> EmptyHeaders = new Dictionary<string, string>();

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
            Assert.That(json, Does.Not.Contain("203.0.113.10"));
            Assert.That(json, Does.Not.Contain("Sensitive Browser"));
            Assert.That(json, Does.Not.Contain("shared-secret"));
            Assert.That(json, Does.Not.Contain("signature"));
            Assert.That(json, Does.Not.Contain("providerKey"));
        }
    }

    [Test]
    public async Task HandleAsyncAddsHeadersAndSignature()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        var handler = CreateHandler(transport, CreateOptions(endpoint));
        var securityEvent = CreateEvent();

        await handler.HandleAsync(securityEvent);

        var request = transport.Requests.Single();
        var headers = request.Headers.ToDictionary(header => header.Key, header => header.Value.Single(), StringComparer.Ordinal);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Headers["X-Ashlar-Event-Id"].Single(), Is.EqualTo(securityEvent.Id.ToString("D")));
            Assert.That(request.Headers["X-Ashlar-Event-Type"].Single(), Is.EqualTo(securityEvent.EventType));
            Assert.That(request.Headers["X-Ashlar-Event-Outcome"].Single(), Is.EqualTo(securityEvent.Outcome));
            Assert.That(request.Headers["X-Ashlar-Webhook-Endpoint"].Single(), Is.EqualTo(endpoint.Name));
            Assert.That(request.Headers["X-Ashlar-Timestamp"].Single(), Is.EqualTo(securityEvent.OccurredAt.ToString("O")));
            Assert.That(request.Headers[AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName].Single(), Is.Not.Empty);
            Assert.That(VerifySignature(
                request.Body,
                headers,
                endpoint.SharedSecret,
                securityEvent.Id,
                endpoint.Name,
                "/security-events",
                TimeProvider.System,
                new AshlarSecurityEventWebhookVerificationOptions
                {
                    TimestampTolerance = TimeSpan.FromMinutes(10),
                    ReplayStore = new RecordingReplayStore()
                }).IsValid, Is.True);
        }
    }

    [Test]
    public void CreateSignatureReturnsKnownHmacSha256Value()
    {
        var signature = AshlarSecurityEventWebhookSignature.CreateSignature(
            "secret",
            "hello"u8,
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso");

        Assert.That(signature, Is.EqualTo("v1=381d2453658bf2e7d70575906681e8d788a5bf14e5d6507c326677837d6f8c24"));
    }

    [Test]
    public void VerifyRequiresReplayStoreByDefault()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now);

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.ReplayStoreRequired));
            Assert.That(result.FailureReason, Is.EqualTo("Replay store required."));
        }
    }

    [Test]
    public void VerifyRequiresReplayStoreWhenOptionsAreConfiguredWithoutStore()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now);

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            new AshlarSecurityEventWebhookVerificationOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.ReplayStoreRequired));
            Assert.That(result.FailureReason, Is.EqualTo("Replay store required."));
        }
    }

    [Test]
    public void VerifyAcceptsValidSignatureWithReplayStore()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now);
        var replayStore = new RecordingReplayStore();

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            new AshlarSecurityEventWebhookVerificationOptions { ReplayStore = replayStore });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsValid, Is.True);
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.Valid));
            Assert.That(result.FailureReason, Is.Empty);
            Assert.That(replayStore.Keys, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public void VerifyRejectsSameSignedRequestAsReplayWhenReplayStoreIsConfigured()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now);
        var replayStore = new RecordingReplayStore();
        var options = new AshlarSecurityEventWebhookVerificationOptions { ReplayStore = replayStore };

        var first = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            options);
        var second = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            options);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.Valid));
            Assert.That(second.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.ReplayDetected));
            Assert.That(second.IsValid, Is.False);
            Assert.That(second.FailureReason, Is.EqualTo("Replay detected."));
            Assert.That(replayStore.Keys, Has.Count.EqualTo(2));
            Assert.That(replayStore.Keys[0], Is.EqualTo(new AshlarSecurityEventWebhookReplayKey(
                "audit",
                new Guid("11111111-1111-1111-1111-111111111111"),
                now,
                AshlarSecurityEventWebhookSignature.SignatureVersion,
                "/security-events?tenant=contoso")));
            Assert.That(replayStore.ExpiresAt, Has.All.EqualTo(now.AddMinutes(5)));
        }
    }

    [Test]
    public void VerifyAcceptsDifferentEventIdWithReplayStore()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var firstEventId = new Guid("11111111-1111-1111-1111-111111111111");
        var secondEventId = new Guid("22222222-2222-2222-2222-222222222222");
        var replayStore = new RecordingReplayStore();
        var options = new AshlarSecurityEventWebhookVerificationOptions { ReplayStore = replayStore };

        var first = VerifySignature(
            "body"u8,
            CreateSignedHeaders(now: now, eventId: firstEventId),
            "secret",
            firstEventId,
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            options);
        var second = VerifySignature(
            "body"u8,
            CreateSignedHeaders(now: now, eventId: secondEventId),
            "secret",
            secondEventId,
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            options);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.Valid));
            Assert.That(second.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.Valid));
            Assert.That(replayStore.Keys.Select(key => key.EventId), Is.EquivalentTo(new[] { firstEventId, secondEventId }));
        }
    }

    [Test]
    public void VerifyReportsStaleTimestampBeforeReplay()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now.AddMinutes(-10));
        var replayStore = new RejectingReplayStore();

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            new AshlarSecurityEventWebhookVerificationOptions
            {
                TimestampTolerance = TimeSpan.FromMinutes(5),
                ReplayStore = replayStore
            });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.TimestampOutsideTolerance));
            Assert.That(replayStore.CallCount, Is.Zero);
        }
    }

    [Test]
    public void VerifyReportsReplayStoreUnavailableWhenReplayStoreFails()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

        var result = VerifySignature(
            "body"u8,
            CreateSignedHeaders(now: now),
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            new AshlarSecurityEventWebhookVerificationOptions { ReplayStore = new ThrowingReplayStore() });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.ReplayStoreUnavailable));
            Assert.That(result.FailureReason, Is.EqualTo("Replay store unavailable."));
        }
    }

    [Test]
    public void VerifyPassesOnlySignedReplayMetadataToReplayStore()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var replayStore = new RecordingReplayStore();
        var headers = CreateSignedHeaders(now: now);
        headers["Authorization"] = "Bearer captured-header";

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            new AshlarSecurityEventWebhookVerificationOptions { ReplayStore = replayStore });

        var key = replayStore.Keys.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.Valid));
            Assert.That(key, Is.EqualTo(new AshlarSecurityEventWebhookReplayKey(
                "audit",
                new Guid("11111111-1111-1111-1111-111111111111"),
                now,
                AshlarSecurityEventWebhookSignature.SignatureVersion,
                "/security-events?tenant=contoso")));
            Assert.That(replayStore.ExpiresAt.Single(), Is.EqualTo(now.AddMinutes(5)));
        }
    }

    [TestCase(AshlarSecurityEventWebhookSignature.SignatureHeaderName, AshlarSecurityEventWebhookVerificationStatus.MissingSignature)]
    [TestCase(AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName, AshlarSecurityEventWebhookVerificationStatus.MissingTimestamp)]
    [TestCase(AshlarSecurityEventWebhookSignature.EventTimestampHeaderName, AshlarSecurityEventWebhookVerificationStatus.MissingEventTimestamp)]
    public void VerifyReportsMissingHeaders(string missingHeader, AshlarSecurityEventWebhookVerificationStatus expectedStatus)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now);
        headers.Remove(missingHeader);

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now));

        Assert.That(result.Status, Is.EqualTo(expectedStatus));
    }

    [TestCase("not-a-timestamp", AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName)]
    [TestCase("+1800000000", AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName)]
    [TestCase("01800000000", AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName)]
    [TestCase(" 1800000000", AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName)]
    [TestCase("9223372036854775807", AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName)]
    [TestCase("not-a-timestamp", AshlarSecurityEventWebhookSignature.EventTimestampHeaderName)]
    [TestCase(" ", AshlarSecurityEventWebhookSignature.SignatureHeaderName)]
    [TestCase("v1=not-hex", AshlarSecurityEventWebhookSignature.SignatureHeaderName)]
    [TestCase("v1=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", AshlarSecurityEventWebhookSignature.SignatureHeaderName)]
    [TestCase("sha256=88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b", AshlarSecurityEventWebhookSignature.SignatureHeaderName)]
    public void VerifyReportsMalformedHeaders(string malformedValue, string headerName)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now);
        headers[headerName] = malformedValue;

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now));

        var expectedStatus = headerName == AshlarSecurityEventWebhookSignature.EventTimestampHeaderName
            ? AshlarSecurityEventWebhookVerificationStatus.MalformedEventTimestamp
            : AshlarSecurityEventWebhookVerificationStatus.MalformedSignature;
        Assert.That(result.Status, Is.EqualTo(expectedStatus));
    }

    [TestCase(-301)]
    [TestCase(301)]
    public void VerifyRejectsTimestampOutsideTolerance(int offsetSeconds)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now.AddSeconds(offsetSeconds));

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            new AshlarSecurityEventWebhookVerificationOptions
            {
                TimestampTolerance = TimeSpan.FromMinutes(5)
            });

        Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.TimestampOutsideTolerance));
    }

    [Test]
    public void VerifyRejectsNegativeUnixTimestampOutsideTolerance()
    {
        var headers = CreateSignedHeaders(now: DateTimeOffset.FromUnixTimeSeconds(-1));

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)),
            new AshlarSecurityEventWebhookVerificationOptions
            {
                TimestampTolerance = TimeSpan.FromMinutes(5)
            });

        Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.TimestampOutsideTolerance));
    }

    [Test]
    public void VerifyReportsMissingSecretBeforeSignatureComparison()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var result = VerifySignature(
            "body"u8,
            CreateSignedHeaders(now: now),
            null,
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now));

        Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.MissingSecret));
    }

    [TestCase("secret", "body", "11111111-1111-1111-1111-111111111111", "audit", "/security-events?tenant=contoso", 1)]
    [TestCase("wrong-secret", "body", "11111111-1111-1111-1111-111111111111", "audit", "/security-events?tenant=contoso", 0)]
    [TestCase("secret", "changed-body", "11111111-1111-1111-1111-111111111111", "audit", "/security-events?tenant=contoso", 0)]
    [TestCase("secret", "body", "22222222-2222-2222-2222-222222222222", "audit", "/security-events?tenant=contoso", 0)]
    [TestCase("secret", "body", "11111111-1111-1111-1111-111111111111", "other", "/security-events?tenant=contoso", 0)]
    [TestCase("secret", "body", "11111111-1111-1111-1111-111111111111", "audit", "/security-events?tenant=other", 0)]
    public void VerifyBindsSecretBodyEventEndpointAndDestination(
        string secret,
        string body,
        string eventId,
        string endpointName,
        string destinationPathAndQuery,
        int expectedValid)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var result = VerifySignature(
            Encoding.UTF8.GetBytes(body),
            CreateSignedHeaders(now: now),
            secret,
            Guid.Parse(eventId),
            endpointName,
            destinationPathAndQuery,
            new StaticTimeProvider(now),
            new AshlarSecurityEventWebhookVerificationOptions { ReplayStore = new RecordingReplayStore() });

        Assert.That(result.IsValid, Is.EqualTo(expectedValid == 1));
        if (expectedValid == 0)
        {
            Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.InvalidSignature));
        }
    }

    [Test]
    public void VerifyBindsEventTimestampHeader()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now);
        headers[AshlarSecurityEventWebhookSignature.EventTimestampHeaderName] = DateTimeOffset.UnixEpoch.ToString("O");

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now));

        Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.InvalidSignature));
    }

    [Test]
    public void VerifyUsesFullLengthConstantTimeComparisonPathForWrongSignature()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now: now);
        headers[AshlarSecurityEventWebhookSignature.SignatureHeaderName] =
            "v1=0000000000000000000000000000000000000000000000000000000000000000";

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now));

        Assert.That(result.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.InvalidSignature));
    }

    [Test]
    public void VerificationFailureReasonsAreSafe()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarSecurityEventWebhookVerificationResult.Valid.IsValid, Is.True);
            Assert.That(AshlarSecurityEventWebhookVerificationResult.Valid.Status, Is.EqualTo(AshlarSecurityEventWebhookVerificationStatus.Valid));
            Assert.That(AshlarSecurityEventWebhookVerificationResult.Valid.FailureReason, Is.Empty);
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MissingSignature).FailureReason, Is.EqualTo("Missing signature."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MalformedSignature).FailureReason, Is.EqualTo("Malformed signature."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MissingTimestamp).FailureReason, Is.EqualTo("Missing signature timestamp."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.TimestampOutsideTolerance).FailureReason, Is.EqualTo("Signature timestamp is outside the accepted tolerance."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.InvalidSignature).FailureReason, Is.EqualTo("Invalid signature."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MissingSecret).FailureReason, Is.EqualTo("Missing shared secret."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MissingEventTimestamp).FailureReason, Is.EqualTo("Missing event timestamp."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MalformedEventTimestamp).FailureReason, Is.EqualTo("Malformed event timestamp."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.ReplayDetected).FailureReason, Is.EqualTo("Replay detected."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.ReplayStoreUnavailable).FailureReason, Is.EqualTo("Replay store unavailable."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.ReplayStoreRequired).FailureReason, Is.EqualTo("Replay store required."));
            Assert.That(new AshlarSecurityEventWebhookVerificationResult((AshlarSecurityEventWebhookVerificationStatus)99).FailureReason, Is.EqualTo("Invalid signature."));
        }
    }

    [Test]
    public void VerifyAcceptsHeaderNamesCaseInsensitively()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var headers = CreateSignedHeaders(now)
            .ToDictionary(header => header.Key.ToLowerInvariant(), header => header.Value, StringComparer.Ordinal);

        var result = VerifySignature(
            "body"u8,
            headers,
            "secret",
            new Guid("11111111-1111-1111-1111-111111111111"),
            "audit",
            "/security-events?tenant=contoso",
            new StaticTimeProvider(now),
            new AshlarSecurityEventWebhookVerificationOptions { ReplayStore = new RecordingReplayStore() });

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void VerifyThrowsForInvalidProgrammerArguments()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => AshlarSecurityEventWebhookSignature.CreateSignature("secret", "body"u8, now, now, Guid.Empty, "audit", " "));
            Assert.Throws<ArgumentException>(() => AshlarSecurityEventWebhookSignature.CreateSignature("secret", "body"u8, now, now, Guid.Empty, "audit", "/security-events\r\nx-test"));
            Assert.Throws<ArgumentOutOfRangeException>(() => VerifySignature(
                "body"u8,
                CreateSignedHeaders(now),
                "secret",
                new Guid("11111111-1111-1111-1111-111111111111"),
                "audit",
                "/security-events?tenant=contoso",
                new StaticTimeProvider(now),
                new AshlarSecurityEventWebhookVerificationOptions { TimestampTolerance = TimeSpan.FromTicks(-1) }));
        }
    }

    [Test]
    public void AddSigningHeadersRemovesStaleSignatureHeadersCaseInsensitively()
    {
        var headers = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["x-ashlar-signature"] = new string('0', 67),
            ["x-ashlar-signature-timestamp"] = "1"
        };

        AddSigningHeaders(
            headers,
            "audit",
            "secret",
            allowUnsigned: false,
            Guid.Empty,
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
            new Uri("https://example.test/security-events"),
            "body"u8,
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(headers, Does.Not.ContainKey("x-ashlar-signature"));
            Assert.That(headers, Does.Not.ContainKey("x-ashlar-signature-timestamp"));
            Assert.That(headers, Does.ContainKey(AshlarSecurityEventWebhookSignature.SignatureHeaderName));
            Assert.That(headers, Does.ContainKey(AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName));
        }
    }

    [Test]
    public void AddSigningHeadersSupportsEmptyHeaderDictionary()
    {
        var headers = new Dictionary<string, string>(StringComparer.Ordinal);

        AddSigningHeaders(
            headers,
            "audit",
            "secret",
            allowUnsigned: false,
            Guid.Empty,
            DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
            new Uri("https://example.test/security-events"),
            "body"u8,
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(headers, Does.ContainKey(AshlarSecurityEventWebhookSignature.SignatureHeaderName));
            Assert.That(headers, Does.ContainKey(AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName));
        }
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
    public async Task HandleAsyncSkipsDisabledEndpointsRegardlessOfOutcomeAllowList()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.Enabled = false;
        endpoint.Outcomes.Add(SecurityEventOutcomes.Failure);
        var handler = CreateHandler(transport, CreateOptions(endpoint));

        await handler.HandleAsync(CreateEvent(outcome: SecurityEventOutcomes.Failure));

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
    public async Task HandleAsyncSendsSuccessAndFailureWhenOutcomeAllowListIsEmpty()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var handler = CreateHandler(transport, CreateOptions(CreateEndpoint()));

        await handler.HandleAsync(CreateEvent(outcome: SecurityEventOutcomes.Success));
        await handler.HandleAsync(CreateEvent(outcome: SecurityEventOutcomes.Failure));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Has.Count.EqualTo(2));
            Assert.That(ReadPayload(transport.Requests[0]).GetProperty("outcome").GetString(), Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(ReadPayload(transport.Requests[1]).GetProperty("outcome").GetString(), Is.EqualTo(SecurityEventOutcomes.Failure));
        }
    }

    [Test]
    public async Task HandleAsyncAppliesSuccessOutcomeAllowList()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.Outcomes.Add(SecurityEventOutcomes.Success);
        var handler = CreateHandler(transport, CreateOptions(endpoint));

        await handler.HandleAsync(CreateEvent(outcome: SecurityEventOutcomes.Success));
        await handler.HandleAsync(CreateEvent(outcome: SecurityEventOutcomes.Failure));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(ReadPayload(transport.Requests.Single()).GetProperty("outcome").GetString(), Is.EqualTo(SecurityEventOutcomes.Success));
        }
    }

    [Test]
    public async Task HandleAsyncAppliesFailureOutcomeAllowList()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.Outcomes.Add(SecurityEventOutcomes.Failure);
        var handler = CreateHandler(transport, CreateOptions(endpoint));

        await handler.HandleAsync(CreateEvent(outcome: SecurityEventOutcomes.Success));
        await handler.HandleAsync(CreateEvent(outcome: SecurityEventOutcomes.Failure));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(ReadPayload(transport.Requests.Single()).GetProperty("outcome").GetString(), Is.EqualTo(SecurityEventOutcomes.Failure));
        }
    }

    [Test]
    public async Task HandleAsyncMatchesOutcomeAllowListCaseInsensitively()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.Outcomes.Add("SUCCESS");
        var handler = CreateHandler(transport, CreateOptions(endpoint));

        await handler.HandleAsync(CreateEvent(outcome: SecurityEventOutcomes.Success));

        Assert.That(transport.Requests, Has.Count.EqualTo(1));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase(" ")]
    [TestCase("success\r\nx-test")]
    public async Task HandleAsyncSkipsMissingOrUnsafeOutcomeWithoutThrowing(string? outcome)
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var handler = CreateHandler(transport, CreateOptions(CreateEndpoint()));

        await handler.HandleAsync(CreateEvent(outcome: outcome));

        Assert.That(transport.Requests, Is.Empty);
    }

    [TestCase(" ")]
    [TestCase("ashlar.sign_in\nfailed")]
    public async Task HandleAsyncSkipsUnsafeEventTypeWithoutThrowing(string eventType)
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var handler = CreateHandler(transport, CreateOptions(CreateEndpoint()));

        await handler.HandleAsync(CreateEvent(eventType: eventType));

        Assert.That(transport.Requests, Is.Empty);
    }

    [Test]
    public void DeliveryFactoryRequiresEventTypeAndOutcomeAllowListsToMatch()
    {
        var eventTypeMismatch = CreateEndpoint("event-type-mismatch", "https://event-type.example.test/security-events");
        eventTypeMismatch.EventTypes.Add("different.event");
        eventTypeMismatch.Outcomes.Add(SecurityEventOutcomes.Success);
        var outcomeMismatch = CreateEndpoint("outcome-mismatch", "https://outcome.example.test/security-events");
        outcomeMismatch.EventTypes.Add("ashlar.sign_in.failed");
        outcomeMismatch.Outcomes.Add(SecurityEventOutcomes.Failure);
        var bothMatch = CreateEndpoint("both-match", "https://both.example.test/security-events");
        bothMatch.EventTypes.Add("ashlar.sign_in.failed");
        bothMatch.Outcomes.Add(SecurityEventOutcomes.Success);
        var factory = new AshlarSecurityEventWebhookDeliveryFactory(Options.Create(CreateOptions(
            eventTypeMismatch,
            outcomeMismatch,
            bothMatch)));

        var deliveries = factory.CreateDeliveries(CreateEvent(outcome: SecurityEventOutcomes.Success));

        Assert.That(deliveries.Single().EndpointName, Is.EqualTo("both-match"));
    }

    [Test]
    public void DeliveryFactoryRejectsUnsignedEndpointUnlessExplicitlyAllowed()
    {
        var endpoint = CreateEndpoint();
        endpoint.SharedSecret = null;
        var factory = new AshlarSecurityEventWebhookDeliveryFactory(Options.Create(CreateOptions(endpoint)));

        Assert.Throws<InvalidOperationException>(() => factory.CreateDeliveries(CreateEvent()));

        endpoint.AllowUnsigned = true;
        Assert.That(factory.CreateDeliveries(CreateEvent()).Single().Headers, Does.Not.ContainKey(AshlarSecurityEventWebhookSignature.SignatureHeaderName));
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
        var sender = new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(transport), logger, destinationValidator: CreateDestinationValidator());

        await sender.SendAsync(CreateDelivery());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(logger.Entries, Has.Count.EqualTo(1));
            Assert.That(logger.Entries[0].Message, Does.Contain("StatusCode=502"));
            Assert.That(logger.Entries[0].Exception, Is.Null);
        }
    }

    [Test]
    public async Task SenderObserverRecordsSuccessfulBestEffortDelivery()
    {
        var observer = new RecordingDeliveryObserver();
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var sender = new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(transport), observer: observer, destinationValidator: CreateDestinationValidator());

        await sender.SendAsync(CreateDelivery());

        var telemetry = observer.Attempts.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(telemetry.DeliveryMode, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.BestEffortDeliveryMode));
            Assert.That(telemetry.EventType, Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(telemetry.EndpointName, Is.EqualTo("audit"));
            Assert.That(telemetry.Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.SuccessOutcome));
            Assert.That(telemetry.FailureKind, Is.Null);
            Assert.That(telemetry.Duration, Is.GreaterThanOrEqualTo(TimeSpan.Zero));
        }
    }

    [Test]
    public async Task SenderObserverRecordsBestEffortHttpStatusFailure()
    {
        var observer = new RecordingDeliveryObserver();
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.BadGateway);
        var sender = new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(transport), observer: observer, destinationValidator: CreateDestinationValidator());

        await sender.SendAsync(CreateDelivery());

        var telemetry = observer.Attempts.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(telemetry.Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome));
            Assert.That(telemetry.FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.HttpStatusFailureKind));
        }
    }

    [Test]
    public void SenderObserverFailureDoesNotBreakDelivery()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var sender = new AshlarSecurityEventWebhookSender(
            new TestHttpClientFactory(transport),
            observer: new ThrowingDeliveryObserver(),
            destinationValidator: CreateDestinationValidator());

        Assert.DoesNotThrowAsync(() => sender.SendAsync(CreateDelivery()));

        Assert.That(transport.Requests, Has.Count.EqualTo(1));
    }

    [Test]
    public void SenderObserverRecordsBestEffortTimeoutFailure()
    {
        var observer = new RecordingDeliveryObserver();
        var transport = new QueueingHttpMessageHandler(_ => throw new OperationCanceledException());
        var sender = new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(transport), observer: observer, destinationValidator: CreateDestinationValidator());

        Assert.ThrowsAsync<OperationCanceledException>(() => sender.SendAsync(CreateDelivery()));

        Assert.That(observer.Attempts.Single().FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.TimeoutFailureKind));
    }

    [Test]
    public void SenderObserverRecordsBestEffortCallerCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var observer = new RecordingDeliveryObserver();
        var transport = new ImmediateThrowHttpMessageHandler(_ => new OperationCanceledException(cancellation.Token));
        var sender = new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(transport), observer: observer, destinationValidator: CreateDestinationValidator());

        cancellation.Cancel();

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), () => sender.SendAsync(CreateDelivery(), cancellation.Token));

        Assert.That(observer.Attempts.Single().FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.CanceledFailureKind));
    }

    [Test]
    public void SenderObserverRecordsBestEffortExceptionFailure()
    {
        var observer = new RecordingDeliveryObserver();
        var transport = new QueueingHttpMessageHandler(_ => throw new InvalidOperationException("transport failed"));
        var sender = new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(transport), observer: observer, destinationValidator: CreateDestinationValidator());

        Assert.ThrowsAsync<InvalidOperationException>(() => sender.SendAsync(CreateDelivery()));

        Assert.That(observer.Attempts.Single().FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind));
    }

    [Test]
    public async Task SendAsyncRejectsUnsafeDestinationBeforeHttpSend()
    {
        var observer = new RecordingDeliveryObserver();
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var sender = new AshlarSecurityEventWebhookSender(
            new TestHttpClientFactory(transport),
            observer: observer,
            destinationValidator: CreateDestinationValidator());
        var delivery = CreateDelivery(new Uri("https://127.0.0.1/security-events"));

        await sender.SendAsync(delivery);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(observer.Attempts.Single().Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome));
            Assert.That(observer.Attempts.Single().FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind));
        }
    }

    [Test]
    public async Task SendAsyncUsesInjectedDestinationValidator()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var sender = new AshlarSecurityEventWebhookSender(
            new TestHttpClientFactory(transport),
            destinationValidator: CreateDestinationValidator());

        await sender.SendAsync(CreateDelivery(new Uri("https://93.184.216.34/security-events")));

        Assert.That(transport.Requests, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task SendAsyncAllowsPrivateDestinationWhenPolicyAllowsPrivateNetworks()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var sender = new AshlarSecurityEventWebhookSender(
            new TestHttpClientFactory(transport),
            destinationValidator: CreateDestinationValidator(AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks));

        await sender.SendAsync(CreateDelivery(new Uri("https://10.0.0.5/security-events")));

        Assert.That(transport.Requests, Has.Count.EqualTo(1));
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
    public void OutboxHandlerThrowsForNullArguments()
    {
        var factory = new AshlarSecurityEventWebhookDeliveryFactory(Options.Create(new AshlarSecurityEventWebhookOptions()));
        var enqueuer = new TestWebhookEnqueuer();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookOutboxHandler(null!, enqueuer));
            Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookOutboxHandler(factory, null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => new AshlarSecurityEventWebhookOutboxHandler(factory, enqueuer).HandleAsync(null!));
        }
    }

    [Test]
    public void OutboxHandlerRespectsCallerCancellation()
    {
        var factory = new AshlarSecurityEventWebhookDeliveryFactory(Options.Create(CreateOptions(CreateEndpoint())));
        var handler = new AshlarSecurityEventWebhookOutboxHandler(factory, new TestWebhookEnqueuer());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), () => handler.HandleAsync(CreateEvent(), cancellation.Token));
    }

    [Test]
    public void CreatePayloadThrowsForNullEvent()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookDeliveryFactory.CreatePayload(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("securityEvent"));
    }

    [TestCase(" ")]
    [TestCase("ashlar.sign_in\nfailed")]
    public void CreateHeadersRejectsUnsafePayloadEventType(string eventType)
    {
        var payload = CreatePayload(eventType);
        var body = AshlarSecurityEventWebhookPayloadSerializer.Serialize(payload);

        var exception = Assert.Throws<ArgumentException>(() =>
            AshlarSecurityEventWebhookDeliveryFactory.CreateHeaders(
                CreateEndpoint(),
                payload,
                body,
                DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)));

        Assert.That(exception?.ParamName, Is.EqualTo("payload.EventType"));
    }

    [Test]
    public void CreateHeadersAddsOutcomeHeaderWhenOutcomeIsPresent()
    {
        var payload = CreatePayloadWithOutcome(SecurityEventOutcomes.Success);
        var body = AshlarSecurityEventWebhookPayloadSerializer.Serialize(payload);

        var headers = AshlarSecurityEventWebhookDeliveryFactory.CreateHeaders(
            CreateEndpoint(),
            payload,
            body,
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

        Assert.That(headers["X-Ashlar-Event-Outcome"], Is.EqualTo(SecurityEventOutcomes.Success));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase(" ")]
    [TestCase("success\r\nx-test")]
    public void CreateHeadersRejectsMissingOrUnsafePayloadOutcome(string? outcome)
    {
        var payload = CreatePayloadWithOutcome(outcome);
        var body = AshlarSecurityEventWebhookPayloadSerializer.Serialize(payload);

        var exception = Assert.Throws<ArgumentException>(() =>
            AshlarSecurityEventWebhookDeliveryFactory.CreateHeaders(
                CreateEndpoint(),
                payload,
                body,
                DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)));

        Assert.That(exception?.ParamName, Is.EqualTo("payload.Outcome"));
    }

    [Test]
    public void CreateSignatureThrowsForNullSecret()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookSignature.CreateSignature(
            null!,
            [],
            DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch,
            Guid.Empty,
            "audit",
            "/security-events"));

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
            new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(transport), destinationValidator: CreateDestinationValidator()),
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

    private static Dictionary<string, string> CreateSignedHeaders(DateTimeOffset now)
    {
        return CreateSignedHeaders(now, new Guid("11111111-1111-1111-1111-111111111111"));
    }

    private static Dictionary<string, string> CreateSignedHeaders(DateTimeOffset now, Guid eventId)
    {
        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName] =
                AshlarSecurityEventWebhookSignature.FormatTimestamp(now),
            [AshlarSecurityEventWebhookSignature.EventTimestampHeaderName] =
                DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).ToString("O"),
            [AshlarSecurityEventWebhookSignature.SignatureHeaderName] =
                AshlarSecurityEventWebhookSignature.CreateSignature(
                    "secret",
                    "body"u8,
                    now,
                    DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
                    eventId,
                    "audit",
                    "/security-events?tenant=contoso")
        };
    }

    private static JsonElement ReadPayload(RecordedRequest request)
    {
        return JsonSerializer.Deserialize<JsonElement>(request.ReadBody());
    }

    private static AshlarSecurityEventWebhookVerificationResult VerifySignature(
        ReadOnlySpan<byte> body,
        IReadOnlyDictionary<string, string> headers,
        string? sharedSecret,
        Guid eventId,
        string endpointName,
        string destinationPathAndQuery,
        TimeProvider timeProvider,
        AshlarSecurityEventWebhookVerificationOptions? options = null)
    {
        return AshlarSecurityEventWebhookSignature.Verify(new AshlarSecurityEventWebhookVerificationRequest
        {
            Body = body.ToArray(),
            Headers = headers,
            SharedSecret = sharedSecret,
            EventId = eventId,
            EndpointName = endpointName,
            DestinationPathAndQuery = destinationPathAndQuery,
            TimeProvider = timeProvider,
            Options = options
        });
    }

    private static void AddSigningHeaders(
        IDictionary<string, string> headers,
        string endpointName,
        string? sharedSecret,
        bool allowUnsigned,
        Guid eventId,
        DateTimeOffset occurredAt,
        Uri uri,
        ReadOnlySpan<byte> body,
        DateTimeOffset signatureTimestamp)
    {
        AshlarSecurityEventWebhookDeliveryFactory.AddSigningHeaders(headers, new AshlarSecurityEventWebhookSigningRequest
        {
            EndpointName = endpointName,
            SharedSecret = sharedSecret,
            AllowUnsigned = allowUnsigned,
            EventId = eventId,
            OccurredAt = occurredAt,
            Uri = uri,
            Body = body.ToArray(),
            SignatureTimestamp = signatureTimestamp
        });
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
        var payload = CreatePayload();
        var body = AshlarSecurityEventWebhookPayloadSerializer.Serialize(payload);
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = uri ?? new Uri("https://example.test/security-events"),
            SharedSecret = "shared-secret"
        };
        return new AshlarSecurityEventWebhookDelivery(
            "audit",
            endpoint.Uri,
            TimeSpan.FromSeconds(10),
            AshlarSecurityEventWebhookDeliveryFactory.CreateHeaders(endpoint, payload, body, DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)),
            payload,
            body);
    }

    private const string AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName = "Ashlar.Webhooks.Tests.Outbox";

    private static AshlarSecurityEventWebhookOutboxEntry CreateOutboxEntry(string? headers = null, string? uri = null)
    {
        var delivery = CreateDelivery();
        return new AshlarSecurityEventWebhookOutboxEntry
        {
            Id = Guid.NewGuid(),
            EndpointName = delivery.EndpointName,
            Uri = uri ?? delivery.Uri.ToString(),
            EventId = delivery.Payload.Id,
            EventType = delivery.Payload.EventType,
            Outcome = delivery.Payload.Outcome ?? string.Empty,
            OccurredAt = delivery.Payload.OccurredAt,
            Body = delivery.Body.ToArray(),
            Headers = headers ?? JsonSerializer.Serialize(delivery.Headers),
            TimeoutMs = (long)delivery.Timeout.TotalMilliseconds,
            AttemptCount = 0
        };
    }

    private static AshlarSecurityEventWebhookOutboxEntry CreateOutboxEntryWithOutcome(string outcome)
    {
        var entry = CreateOutboxEntry();
        return new AshlarSecurityEventWebhookOutboxEntry
        {
            Id = entry.Id,
            EndpointName = entry.EndpointName,
            Uri = entry.Uri,
            EventId = entry.EventId,
            EventType = entry.EventType,
            Outcome = outcome,
            OccurredAt = entry.OccurredAt,
            Body = entry.Body,
            Headers = entry.Headers,
            TimeoutMs = entry.TimeoutMs,
            AttemptCount = entry.AttemptCount
        };
    }

    private static AshlarSecurityEventWebhookOutboxDispatchContext CreateOutboxDispatchContext(
        HttpMessageHandler transport,
        IAshlarSecurityEventWebhookDeliveryObserver? observer,
        List<Exception>? failed = null)
    {
        return new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, transport),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (_, _) => Task.FromResult(true),
            (_, exception, _) =>
            {
                failed?.Add(exception);
                return Task.CompletedTask;
            },
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            CreateOptions(CreateEndpoint()),
            TimeProvider.System,
            observer);
    }

    private static AshlarSecurityEventWebhookDestinationValidator CreateDestinationValidator()
    {
        return CreateDestinationValidator(AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly);
    }

    private static AshlarSecurityEventWebhookDestinationValidator CreateDestinationValidator(
        AshlarSecurityEventWebhookDestinationPolicy destinationPolicy)
    {
        return new AshlarSecurityEventWebhookDestinationValidator(
            new StaticDestinationResolver(),
            Options.Create(new AshlarSecurityEventWebhookOptions { DestinationPolicy = destinationPolicy }));
    }

    private static AshlarSecurityEventWebhookPayload CreatePayload()
    {
        return AshlarSecurityEventWebhookDeliveryFactory.CreatePayload(CreateEvent());
    }

    private static AshlarSecurityEventWebhookPayload CreatePayload(string eventType)
    {
        return CreatePayload(eventType, SecurityEventOutcomes.Failure);
    }

    private static AshlarSecurityEventWebhookPayload CreatePayloadWithOutcome(string? outcome)
    {
        return CreatePayload("ashlar.sign_in.failed", outcome);
    }

    private static AshlarSecurityEventWebhookPayload CreatePayload(string eventType, string? outcome)
    {
        return new AshlarSecurityEventWebhookPayload
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            OccurredAt = DateTimeOffset.UtcNow,
            Outcome = outcome!
        };
    }

    private static AshlarSecurityEvent CreateEvent(
        string? outcome = SecurityEventOutcomes.Failure,
        string eventType = "ashlar.sign_in.failed")
    {
        return new AshlarSecurityEvent
        {
            Id = new Guid("11111111-1111-1111-1111-111111111111"),
            EventType = eventType,
            OccurredAt = new DateTimeOffset(2026, 5, 24, 12, 0, 0, TimeSpan.Zero),
            UserId = new Guid("22222222-2222-2222-2222-222222222222"),
            TenantId = new Guid("33333333-3333-3333-3333-333333333333"),
            ActorUserId = new Guid("44444444-4444-4444-4444-444444444444"),
            SessionId = new Guid("55555555-5555-5555-5555-555555555555"),
            Provider = new AuthenticationProviderKey(ProviderType.Oidc, "Contoso"),
            IpAddress = "203.0.113.10",
            UserAgent = "Sensitive Browser",
            CorrelationId = "correlation-1",
            Outcome = outcome,
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
    public void SenderThrowsForNullDestinationValidator()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookSender(
            new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.Accepted))));

        Assert.That(exception?.ParamName, Is.EqualTo("destinationValidator"));
    }

    [Test]
    public void SenderThrowsForNullDelivery()
    {
        var sender = new AshlarSecurityEventWebhookSender(new TestHttpClientFactory(new RecordingHttpMessageHandler(HttpStatusCode.Accepted)), destinationValidator: CreateDestinationValidator());

        var exception = Assert.ThrowsAsync<ArgumentNullException>(async () => await sender.SendAsync(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("delivery"));
    }

    [Test]
    public void DeliveryThrowsForInvalidArguments()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery(" ", new Uri("https://example.test"), TimeSpan.FromSeconds(1), EmptyHeaders, CreatePayload()))?.ParamName, Is.EqualTo("endpointName"));
            Assert.That(Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookDelivery("audit", null!, TimeSpan.FromSeconds(1), EmptyHeaders, CreatePayload()))?.ParamName, Is.EqualTo("uri"));
            Assert.That(Assert.Throws<ArgumentOutOfRangeException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.Zero, EmptyHeaders, CreatePayload()))?.ParamName, Is.EqualTo("timeout"));
            Assert.That(Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), null!, CreatePayload()))?.ParamName, Is.EqualTo("headers"));
            Assert.That(Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), EmptyHeaders, null!))?.ParamName, Is.EqualTo("payload"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit\r\nbad", new Uri("https://example.test"), TimeSpan.FromSeconds(1), EmptyHeaders, CreatePayload()))?.ParamName, Is.EqualTo("endpointName"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), EmptyHeaders, CreatePayload(" ")))?.ParamName, Is.EqualTo("payload.EventType"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), EmptyHeaders, CreatePayload("bad\r\nevent")))?.ParamName, Is.EqualTo("payload.EventType"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), EmptyHeaders, CreatePayloadWithOutcome(" ")))?.ParamName, Is.EqualTo("payload.Outcome"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), EmptyHeaders, CreatePayloadWithOutcome("success\n")))?.ParamName, Is.EqualTo("payload.Outcome"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), EmptyHeaders, CreatePayload(), ReadOnlyMemory<byte>.Empty))?.ParamName, Is.EqualTo("body"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), new Dictionary<string, string> { ["bad\r\nname"] = "value" }, CreatePayload()))?.ParamName, Is.EqualTo("headers"));
            Assert.That(Assert.Throws<ArgumentException>(() => new AshlarSecurityEventWebhookDelivery("audit", new Uri("https://example.test"), TimeSpan.FromSeconds(1), new Dictionary<string, string> { ["X-Test"] = "bad\r\nvalue" }, CreatePayload()))?.ParamName, Is.EqualTo("headers"));
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

    [Test]
    public void NoOpObserverThrowsForNullTelemetry()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance.RecordDeliveryAttempt(null!));

        Assert.That(exception?.ParamName, Is.EqualTo("telemetry"));
    }

    [Test]
    public async Task SharedOutboxDispatchObserverRecordsDurableSuccessAndFailure()
    {
        var observer = new RecordingDeliveryObserver();
        var sent = new List<Guid>();
        var failed = new List<Guid>();
        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, new QueueingHttpMessageHandler(
                _ => new HttpResponseMessage(HttpStatusCode.Accepted),
                _ => new HttpResponseMessage(HttpStatusCode.BadGateway))),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (id, _) =>
            {
                sent.Add(id);
                return Task.FromResult(true);
            },
            (entry, _, _) =>
            {
                failed.Add(entry.Id);
                return Task.CompletedTask;
            },
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            CreateOptions(CreateEndpoint()),
            TimeProvider.System,
            observer);
        var entry = CreateOutboxEntry();

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, context, CancellationToken.None);
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, context, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sent, Has.Count.EqualTo(1));
            Assert.That(failed, Has.Count.EqualTo(1));
            Assert.That(observer.Attempts[0].DeliveryMode, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.DurableOutboxDeliveryMode));
            Assert.That(observer.Attempts[0].Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.SuccessOutcome));
            Assert.That(observer.Attempts[1].FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.HttpStatusFailureKind));
            Assert.That(observer.Attempts[1].EventType, Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(observer.Attempts[1].EndpointName, Is.EqualTo("audit"));
        }
    }

    [Test]
    public async Task SharedOutboxDispatchObserverFailureDoesNotBreakDelivery()
    {
        var sent = new List<Guid>();
        var failed = new List<Guid>();
        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, new QueueingHttpMessageHandler(
                _ => new HttpResponseMessage(HttpStatusCode.Accepted),
                _ => new HttpResponseMessage(HttpStatusCode.BadGateway))),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (id, _) =>
            {
                sent.Add(id);
                return Task.FromResult(true);
            },
            (entry, _, _) =>
            {
                failed.Add(entry.Id);
                return Task.CompletedTask;
            },
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            CreateOptions(CreateEndpoint()),
            TimeProvider.System,
            new ThrowingDeliveryObserver());

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(CreateOutboxEntry(), context, CancellationToken.None);
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(CreateOutboxEntry(), context, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sent, Has.Count.EqualTo(1));
            Assert.That(failed, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task SharedOutboxDispatchDoesNotMarkFailedWhenSentStateIsNotPersisted()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var observer = new RecordingDeliveryObserver();
        var failed = false;
        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, transport),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (_, _) => Task.FromResult(false),
            (_, _, _) =>
            {
                failed = true;
                return Task.CompletedTask;
            },
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            CreateOptions(CreateEndpoint()),
            TimeProvider.System,
            observer);

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(CreateOutboxEntry(), context, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(failed, Is.False);
            Assert.That(observer.Attempts, Is.Empty);
        }
    }

    [Test]
    public void SharedOutboxDispatchDoesNotMarkFailedWhenSentStatePersistenceThrows()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var observer = new RecordingDeliveryObserver();
        var persistenceException = new InvalidOperationException("mark sent failed");
        var failed = false;
        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, transport),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (_, _) => throw persistenceException,
            (_, _, _) =>
            {
                failed = true;
                return Task.CompletedTask;
            },
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            CreateOptions(CreateEndpoint()),
            TimeProvider.System,
            observer);

        var exception = Assert.ThrowsAsync<InvalidOperationException>(() =>
            AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(CreateOutboxEntry(), context, CancellationToken.None));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.SameAs(persistenceException));
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
            Assert.That(failed, Is.False);
            Assert.That(observer.Attempts, Is.Empty);
        }
    }

    [Test]
    public void SharedOutboxDispatchObserverRecordsDurableCallerCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var observer = new RecordingDeliveryObserver();
        var context = CreateOutboxDispatchContext(
            new ImmediateThrowHttpMessageHandler(_ => new OperationCanceledException(cancellation.Token)),
            observer);

        cancellation.Cancel();

        Assert.ThrowsAsync(Is.InstanceOf<OperationCanceledException>(), () => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(CreateOutboxEntry(), context, cancellation.Token));

        Assert.That(observer.Attempts.Single().FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.CanceledFailureKind));
    }

    [Test]
    public async Task SharedOutboxDispatchObserverRecordsDurableTimeoutAndExceptionFailures()
    {
        var observer = new RecordingDeliveryObserver();
        var failed = new List<Exception>();
        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, new QueueingHttpMessageHandler(
                _ => throw new OperationCanceledException(),
                _ => throw new InvalidOperationException("transport failed"))),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (_, _) => Task.FromResult(true),
            (_, exception, _) =>
            {
                failed.Add(exception);
                return Task.CompletedTask;
            },
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            CreateOptions(CreateEndpoint()),
            TimeProvider.System,
            observer);

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(CreateOutboxEntry(), context, CancellationToken.None);
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(CreateOutboxEntry(), context, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failed, Has.Count.EqualTo(2));
            Assert.That(observer.Attempts[0].FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.TimeoutFailureKind));
            Assert.That(observer.Attempts[1].FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind));
        }
    }

    [Test]
    public async Task SharedOutboxDispatchRejectsUnsafeDestinationBeforeHttpSend()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var failed = new List<Exception>();
        var endpoint = CreateEndpoint();
        endpoint.Uri = new Uri("https://127.0.0.1/security-events");
        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, transport),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            1,
            (_, _) => Task.FromResult(true),
            (_, exception, _) =>
            {
                failed.Add(exception);
                return Task.CompletedTask;
            },
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            CreateOptions(endpoint),
            TimeProvider.System);

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            CreateOutboxEntry(uri: "https://127.0.0.1/security-events"),
            context,
            CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(failed.Single(), Is.TypeOf<AshlarSecurityEventWebhookUnsafeDestinationException>());
        }
    }

    [Test]
    public async Task SharedOutboxDispatchHandlesNoObserverAndMissingHeaders()
    {
        var observer = new RecordingDeliveryObserver();
        var missingHeaders = CreateOutboxEntry("{}");
        var nullHeaders = CreateOutboxEntry("null");
        var missingHeadersTransport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var nullHeadersTransport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            missingHeaders,
            CreateOutboxDispatchContext(missingHeadersTransport, observer),
            CancellationToken.None);
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            nullHeaders,
            CreateOutboxDispatchContext(nullHeadersTransport, observer),
            CancellationToken.None);
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            CreateOutboxEntry(),
            CreateOutboxDispatchContext(new RecordingHttpMessageHandler(HttpStatusCode.Accepted), null),
            CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(observer.Attempts, Has.Count.EqualTo(2));
            Assert.That(observer.Attempts[0].EventType, Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(observer.Attempts[0].EndpointName, Is.EqualTo("audit"));
            Assert.That(observer.Attempts[1].EventType, Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(observer.Attempts[1].EndpointName, Is.EqualTo("audit"));
            Assert.That(missingHeadersTransport.Requests.Single().Headers["X-Ashlar-Event-Outcome"].Single(), Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(nullHeadersTransport.Requests.Single().Headers["X-Ashlar-Event-Outcome"].Single(), Is.EqualTo(SecurityEventOutcomes.Failure));
        }
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("success\n")]
    public async Task SharedOutboxDispatchFailsSafelyWhenStoredOutcomeIsInvalid(string outcome)
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var failed = new List<Exception>();
        var observer = new RecordingDeliveryObserver();
        var entry = CreateOutboxEntryWithOutcome(outcome);

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            entry,
            CreateOutboxDispatchContext(transport, observer, failed),
            CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(failed.Single(), Is.InstanceOf<Exception>());
            Assert.That(observer.Attempts.Single().Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome));
            Assert.That(observer.Attempts.Single().EventType, Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(observer.Attempts.Single().EndpointName, Is.EqualTo("audit"));
        }
    }

    [Test]
    public void SharedOutboxDispatchRejectsInvalidContext()
    {
        var entry = CreateOutboxEntry();
        var valid = CreateOutboxDispatchContext(new RecordingHttpMessageHandler(HttpStatusCode.Accepted), new RecordingDeliveryObserver());

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(null!, valid, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, null!, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, valid with { HttpClientFactory = null! }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, valid with { HttpClientName = " " }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, valid with { MarkAsSentAsync = null! }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, valid with { MarkAsFailedAsync = null! }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, valid with { LogDeliveryFailed = null! }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, valid with { DestinationValidator = null! }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, valid with { WebhookOptions = null! }, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, valid with { TimeProvider = null! }, CancellationToken.None));
        }
    }

    [Test]
    public async Task SharedOutboxDispatchRecordsFailureWithNullPersistedHeaders()
    {
        var observer = new RecordingDeliveryObserver();
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            CreateOutboxEntry(headers: "null", uri: "https://127.0.0.1/security-events"),
            CreateOutboxDispatchContext(new RecordingHttpMessageHandler(HttpStatusCode.Accepted), observer),
            CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(observer.Attempts.Single().Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome));
            Assert.That(observer.Attempts.Single().EventType, Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(observer.Attempts.Single().EndpointName, Is.EqualTo("audit"));
        }
    }

    [Test]
    public async Task SharedOutboxDispatchRecordsFailureWithPresentHeadersMissingEventMetadata()
    {
        var observer = new RecordingDeliveryObserver();
        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            CreateOutboxEntry(headers: """{"X-Other":"value"}""", uri: "https://127.0.0.1/security-events"),
            CreateOutboxDispatchContext(new RecordingHttpMessageHandler(HttpStatusCode.Accepted), observer),
            CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(observer.Attempts.Single().Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome));
            Assert.That(observer.Attempts.Single().EventType, Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(observer.Attempts.Single().EndpointName, Is.EqualTo("audit"));
        }
    }

    [Test]
    public async Task SharedOutboxDispatchRecordsEntryMetadataWhenHeaderDeserializationFails()
    {
        var observer = new RecordingDeliveryObserver();
        var failed = new List<Exception>();
        var context = CreateOutboxDispatchContext(
            new RecordingHttpMessageHandler(HttpStatusCode.Accepted),
            observer,
            failed);

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            CreateOutboxEntry(headers: "{"),
            context,
            CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(failed.Single(), Is.TypeOf<JsonException>());
            Assert.That(observer.Attempts.Single().Outcome, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome));
            Assert.That(observer.Attempts.Single().FailureKind, Is.EqualTo(AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind));
            Assert.That(observer.Attempts.Single().EventType, Is.EqualTo("ashlar.sign_in.failed"));
            Assert.That(observer.Attempts.Single().EndpointName, Is.EqualTo("audit"));
        }
    }

    [Test]
    public async Task SharedOutboxDispatchRegeneratesSigningHeadersBeforeSend()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var sent = new List<Guid>();
        var endpoint = CreateEndpoint();
        endpoint.Uri = new Uri("https://EXAMPLE.test:443/security-events");
        endpoint.SharedSecret = "current-secret";
        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, transport),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (id, _) =>
            {
                sent.Add(id);
                return Task.FromResult(true);
            },
            (_, _, _) => Task.CompletedTask,
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            CreateOptions(endpoint),
            TimeProvider.System);
        var entry = CreateOutboxEntry();
        var staleHeaders = JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Headers)!;
        staleHeaders[AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName.ToLowerInvariant()] = "1";
        staleHeaders[AshlarSecurityEventWebhookSignature.SignatureHeaderName.ToLowerInvariant()] =
            AshlarSecurityEventWebhookSignature.CreateSignature(
                "stale-secret",
                entry.Body,
                DateTimeOffset.FromUnixTimeSeconds(1),
                entry.OccurredAt,
                entry.EventId,
                entry.EndpointName,
                "/security-events");
        entry = CreateOutboxEntry(JsonSerializer.Serialize(staleHeaders));

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(entry, context, CancellationToken.None);

        var request = transport.Requests.Single();
        var sentHeaders = request.Headers.ToDictionary(header => header.Key, header => header.Value.Single(), StringComparer.Ordinal);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(sent, Has.Count.EqualTo(1));
            Assert.That(sentHeaders[AshlarSecurityEventWebhookSignature.SignatureHeaderName], Is.Not.EqualTo(staleHeaders[AshlarSecurityEventWebhookSignature.SignatureHeaderName.ToLowerInvariant()]));
            Assert.That(VerifySignature(
                request.Body,
                sentHeaders,
                "current-secret",
                entry.EventId,
                entry.EndpointName,
                "/security-events",
                TimeProvider.System,
                new AshlarSecurityEventWebhookVerificationOptions
                {
                    TimestampTolerance = TimeSpan.FromMinutes(10),
                    ReplayStore = new RecordingReplayStore()
                }).IsValid, Is.True);
        }
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task SharedOutboxDispatchTerminallyDiscardsDisabledOrRetargetedEndpoint(bool disabled)
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var endpoint = CreateEndpoint();
        endpoint.Enabled = !disabled;
        if (!disabled)
        {
            endpoint.Uri = new Uri("https://example.test/retargeted");
        }

        AshlarSecurityEventWebhookOutboxFailureUpdate? failure = null;
        bool? loggedAsFinal = null;
        var now = DateTimeOffset.UtcNow;
        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, transport),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (_, _) => Task.FromResult(true),
            (entry, exception, _) =>
            {
                failure = AshlarSecurityEventWebhookOutboxDispatch.CreateFailureUpdate(
                    entry.AttemptCount, 3, TimeSpan.FromMinutes(1), now, exception);
                return Task.CompletedTask;
            },
            (_, _, finalFailure, _) => loggedAsFinal = finalFailure,
            CreateDestinationValidator(),
            CreateOptions(endpoint),
            TimeProvider.System);

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            CreateOutboxEntry(headers: disabled ? "{" : null, uri: disabled ? "not a uri" : null),
            context,
            CancellationToken.None);
        var exhaustedRetry = AshlarSecurityEventWebhookOutboxDispatch.CreateFailureUpdate(
            2, 3, TimeSpan.FromMinutes(1), now, new HttpRequestException());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(loggedAsFinal, Is.True);
            Assert.That(failure?.FailedAt, Is.EqualTo(now));
            Assert.That(failure?.AvailableAt, Is.EqualTo(now));
            Assert.That(failure?.AttemptCount, Is.EqualTo(1));
            Assert.That(exhaustedRetry.FailedAt, Is.EqualTo(now));
        }
    }

    [Test]
    public async Task SharedOutboxDispatchIgnoresPersistedContentTypeHeader()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var entry = CreateOutboxEntry();
        var headers = JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Headers)!;
        headers["Content-Type"] = "text/plain";
        headers["Content-Length"] = "1";

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            CreateOutboxEntry(JsonSerializer.Serialize(headers)),
            CreateOutboxDispatchContext(transport, new RecordingDeliveryObserver()),
            CancellationToken.None);

        var request = transport.Requests.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.ContentType, Is.EqualTo("application/json"));
            Assert.That(request.Headers, Does.Not.ContainKey("Content-Type"));
            Assert.That(request.Headers, Does.Not.ContainKey("Content-Length"));
        }
    }

    [Test]
    public async Task SharedOutboxDispatchReplacesDifferentlyCasedPersistedBaseHeaders()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var entry = CreateOutboxEntry();
        var headers = JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Headers)!;
        headers.Remove("X-Ashlar-Event-Id");
        headers.Remove("X-Ashlar-Event-Type");
        headers.Remove("X-Ashlar-Event-Outcome");
        headers.Remove("X-Ashlar-Webhook-Endpoint");
        headers.Remove("X-Ashlar-Timestamp");
        headers["x-ashlar-event-id"] = Guid.Empty.ToString("D");
        headers["x-ashlar-event-type"] = "wrong.event";
        headers["x-ashlar-event-outcome"] = "success";
        headers["x-ashlar-webhook-endpoint"] = "wrong";
        headers["x-ashlar-timestamp"] = DateTimeOffset.UnixEpoch.ToString("O");

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(
            CreateOutboxEntry(JsonSerializer.Serialize(headers)),
            CreateOutboxDispatchContext(transport, new RecordingDeliveryObserver()),
            CancellationToken.None);

        var request = transport.Requests.Single();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Headers.Keys.Count(key => string.Equals(key, "X-Ashlar-Event-Id", StringComparison.OrdinalIgnoreCase)), Is.EqualTo(1));
            Assert.That(request.Headers.Keys.Count(key => string.Equals(key, "X-Ashlar-Event-Type", StringComparison.OrdinalIgnoreCase)), Is.EqualTo(1));
            Assert.That(request.Headers.Keys.Count(key => string.Equals(key, "X-Ashlar-Event-Outcome", StringComparison.OrdinalIgnoreCase)), Is.EqualTo(1));
            Assert.That(request.Headers.Keys.Count(key => string.Equals(key, "X-Ashlar-Webhook-Endpoint", StringComparison.OrdinalIgnoreCase)), Is.EqualTo(1));
            Assert.That(request.Headers.Keys.Count(key => string.Equals(key, "X-Ashlar-Timestamp", StringComparison.OrdinalIgnoreCase)), Is.EqualTo(1));
            Assert.That(request.Headers["x-ashlar-event-id"].Single(), Is.EqualTo(entry.EventId.ToString("D")));
            Assert.That(request.Headers["x-ashlar-event-type"].Single(), Is.EqualTo(entry.EventType));
            Assert.That(request.Headers["x-ashlar-event-outcome"].Single(), Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(request.Headers["x-ashlar-webhook-endpoint"].Single(), Is.EqualTo(entry.EndpointName));
            Assert.That(request.Headers["x-ashlar-timestamp"].Single(), Is.EqualTo(entry.OccurredAt.ToString("O")));
        }
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task SharedOutboxDispatchFailsSafelyWhenSigningConfigurationIsUnavailable(bool missingEndpoint)
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var failed = new List<Exception>();
        var options = missingEndpoint ? new AshlarSecurityEventWebhookOptions() : CreateOptions(CreateEndpoint());
        if (!missingEndpoint)
        {
            options.Endpoints.Single().SharedSecret = null;
        }

        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, transport),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (_, _) => Task.FromResult(true),
            (_, exception, _) =>
            {
                failed.Add(exception);
                return Task.CompletedTask;
            },
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            options,
            TimeProvider.System);

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(CreateOutboxEntry(), context, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(failed.Single(), Is.TypeOf<InvalidOperationException>());
            if (missingEndpoint)
            {
                Assert.That(failed.Single().Message, Does.Contain("'audit'"));
            }
        }
    }

    [Test]
    public async Task SharedOutboxDispatchRequiresExactEndpointIdentityForSigning()
    {
        var transport = new RecordingHttpMessageHandler(HttpStatusCode.Accepted);
        var failed = new List<Exception>();
        var endpoint = CreateEndpoint();
        endpoint.Name = "Audit";
        var context = new AshlarSecurityEventWebhookOutboxDispatchContext(
            new NamedHttpClientFactory(AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName, transport),
            AshlarSecurityEventWebhookOutboxDispatchTestsHttpClientName,
            3,
            (_, _) => Task.FromResult(true),
            (_, exception, _) =>
            {
                failed.Add(exception);
                return Task.CompletedTask;
            },
            (_, _, _, _) => { },
            CreateDestinationValidator(),
            CreateOptions(endpoint),
            TimeProvider.System);

        await AshlarSecurityEventWebhookOutboxDispatch.DispatchAsync(CreateOutboxEntry(), context, CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transport.Requests, Is.Empty);
            Assert.That(failed.Single(), Is.TypeOf<InvalidOperationException>());
            Assert.That(failed.Single().Message, Does.Contain("'audit'"));
        }
    }

    private sealed class TestWebhookSender : IAshlarSecurityEventWebhookSender
    {
        public Task<AshlarSecurityEventWebhookSendResult> SendAsync(
            AshlarSecurityEventWebhookDelivery delivery,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(AshlarSecurityEventWebhookSendResult.Sent);
        }
    }

    private sealed class TestWebhookEnqueuer : IAshlarSecurityEventWebhookEnqueuer
    {
        public Task EnqueueAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingDeliveryObserver : IAshlarSecurityEventWebhookDeliveryObserver
    {
        public List<AshlarSecurityEventWebhookDeliveryTelemetry> Attempts { get; } = [];

        public void RecordDeliveryAttempt(AshlarSecurityEventWebhookDeliveryTelemetry telemetry)
        {
            Attempts.Add(telemetry);
        }
    }

    private sealed class ThrowingDeliveryObserver : IAshlarSecurityEventWebhookDeliveryObserver
    {
        public void RecordDeliveryAttempt(AshlarSecurityEventWebhookDeliveryTelemetry telemetry)
        {
            throw new InvalidOperationException("Observer failed.");
        }
    }

    private sealed class NamedHttpClientFactory(string expectedName, HttpMessageHandler transport) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            Assert.That(name, Is.EqualTo(expectedName));
            return new HttpClient(transport, disposeHandler: false);
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

    private sealed class ImmediateThrowHttpMessageHandler(Func<HttpRequestMessage, Exception> exceptionFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw exceptionFactory(request);
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

    private sealed class RecordingReplayStore : IAshlarSecurityEventWebhookReplayStore
    {
        private readonly HashSet<AshlarSecurityEventWebhookReplayKey> _accepted = [];

        public List<AshlarSecurityEventWebhookReplayKey> Keys { get; } = [];

        public List<DateTimeOffset> ExpiresAt { get; } = [];

        public bool TryAccept(AshlarSecurityEventWebhookReplayKey key, DateTimeOffset expiresAt)
        {
            Keys.Add(key);
            ExpiresAt.Add(expiresAt);
            return _accepted.Add(key);
        }
    }

    private sealed class RejectingReplayStore : IAshlarSecurityEventWebhookReplayStore
    {
        public int CallCount { get; private set; }

        public bool TryAccept(AshlarSecurityEventWebhookReplayKey key, DateTimeOffset expiresAt)
        {
            CallCount++;
            return false;
        }
    }

    private sealed class ThrowingReplayStore : IAshlarSecurityEventWebhookReplayStore
    {
        public bool TryAccept(AshlarSecurityEventWebhookReplayKey key, DateTimeOffset expiresAt)
        {
            throw new InvalidOperationException("Store failure.");
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
