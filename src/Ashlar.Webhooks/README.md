# Ashlar.Webhooks

Best-effort webhook delivery for Ashlar security events.

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

Webhook destinations are validated before delivery. Endpoints must use HTTPS, must not include user info or fragments, and are checked against the configured destination policy. Requests are signed with the current Ashlar security event webhook signature format when `SharedSecret` is configured. Endpoints without a shared secret are rejected unless `AllowUnsigned = true` is set explicitly.

Endpoints can opt into allow-list filtering before delivery. Leave `EventTypes` empty to receive every security event type, or add specific event type strings to receive only those events. Leave `Outcomes` empty to receive both success and failure events, or add outcome strings such as `"success"` or `"failure"` to receive only matching outcomes. Event type and outcome matching are case-insensitive, and both filters must match when both allow-lists are configured.

Webhook requests include `X-Ashlar-Event-Outcome` for the security event outcome. Events without a safe concrete outcome value are skipped by webhook delivery.

## Testing A Configured Endpoint

Applications can test one configured security event webhook endpoint without recording a real security event and without writing to a durable outbox:

```csharp
var tester = services.GetRequiredService<IAshlarSecurityEventWebhookEndpointTester>();
var result = await tester.TestAsync("audit", cancellationToken);

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
- `MissingSharedSecret`
- `DeliveryFailed`
- `TimedOut`
- `Canceled`

`FailureReason` is safe for operational diagnostics and does not expose full destination URIs, shared secrets, raw headers, or raw bodies.
