# Ashlar.Webhooks

Webhook delivery for Ashlar security events.

## Security Event Webhooks

Register best-effort security event webhook delivery with:

```csharp
services.AddAshlarSecurityEventWebhooks(options =>
{
    options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
    {
        Name = "audit",
        Uri = new Uri("https://webhooks.example.com/ashlar/security-events"),
        SharedSecret = builder.Configuration["Ashlar:Webhooks:AuditSecret"]
    });
});
```

Webhook destinations are validated before delivery. Endpoints must use HTTPS, must not include user info or fragments, and are checked against the configured destination policy. Requests are signed with the current Ashlar security event webhook signature format when `SharedSecret` is configured. Use a randomly generated secret of at least 32 UTF-8 bytes. Endpoints without a shared secret are rejected unless `AllowUnsigned = true` is set explicitly; any supplied secret must still meet the minimum length.

Ashlar-owned webhook HTTP clients always disable automatic redirects and validate the connected remote IP address. The optional HTTP client callback is limited to safe `HttpClient` settings such as timeout and default headers; replacing the primary handler is intentionally unsupported because it would bypass SSRF protections and redirect assumptions.

Receivers should verify signatures with `AshlarSecurityEventWebhookSignature.Verify`. Configure `AshlarSecurityEventWebhookVerificationOptions.ReplayStore` to atomically accept each replay key once until the supplied expiry instant. Without a replay store, verification fails closed with `ReplayStoreRequired` because a captured request can be replayed while its signature timestamp remains within tolerance. Keep event processing idempotent even when verification is valid. Replay stores should persist only the provided replay key metadata and must not store webhook secrets, raw bodies, full URLs, headers, or payloads.

Endpoints can opt into allow-list filtering before delivery. Leave `EventTypes` empty to receive every security event type, or add specific event type strings to receive only those events. Leave `Outcomes` empty to receive both success and failure events, or add outcome strings such as `"success"` or `"failure"` to receive only matching outcomes. Event type and outcome matching are case-insensitive, and both filters must match when both allow-lists are configured.

Webhook requests include `X-Ashlar-Event-Outcome` for the security event outcome. Events without a safe concrete outcome value are skipped by webhook delivery.

## Durable Security Event Webhook Outbox

Register durable security event webhook outbox enqueue with the shared endpoint options and a provider-backed outbox:

```csharp
services.AddAshlarSecurityEventWebhookOutbox(options =>
{
    options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
    {
        Name = "audit",
        Uri = new Uri("https://webhooks.example.com/ashlar/security-events"),
        SharedSecret = builder.Configuration["Ashlar:Webhooks:AuditSecret"]
    });
});
services.AddAshlarPostgresSecurityEventWebhookOutbox();
// or: services.AddAshlarSqliteSecurityEventWebhookOutbox();
```

Outbox enqueue runs inside the protected Ashlar transaction when one is active. Enqueue failures fail the protected operation, and rollback abandons the protected mutation, audit record, and webhook outbox row together.

Webhook-outbox browsing, retry, and discard are global operational administration and require an explicit `OperationalAdministrationScope.Global` request scope.

## Testing A Configured Endpoint

Applications can test one configured security event webhook endpoint without recording a real security event and without writing to a durable outbox:

```csharp
var tester = services.GetRequiredService<IAshlarSecurityEventWebhookEndpointTester>();
var result = await tester.TestAsync(actor, "audit", cancellationToken);

if (result.Status == AshlarSecurityEventWebhookEndpointTestStatus.Sent)
{
    // The endpoint accepted the synthetic test request.
}
```

The tester sends a synthetic `ashlar.webhook.test` request through the same sender path used by best-effort delivery, including destination validation, timeout handling, headers, and signing. Endpoint event type and outcome filters do not block manual tests, but disabled endpoints do.

The synthetic test body is intentionally minimal and contains only:

- `id`
- `eventType`
- `occurredAt`

It does not include user ids, tenant ids, actor ids, session ids, provider details, correlation ids, metadata, secrets, raw headers, raw request bodies, or application data.

`AshlarSecurityEventWebhookEndpointTestResult.Status` reports one of:

- `Sent`
- `EndpointNotFound`
- `EndpointDisabled`
- `DestinationRejected`
- `InvalidSharedSecret`
- `DeliveryFailed`
- `TimedOut`
- `Canceled`

`FailureReason` is safe for operational diagnostics and does not expose full destination URIs, shared secrets, raw headers, or raw bodies.
