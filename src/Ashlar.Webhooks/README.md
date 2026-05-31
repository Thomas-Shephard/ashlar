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

The tester sends a synthetic `ashlar.webhook.test` request through the same sender path used by best-effort delivery, including destination validation, timeout handling, headers, and signing. Endpoint event type filters do not block manual tests, but disabled endpoints do.

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
