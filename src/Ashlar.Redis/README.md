# Ashlar.Redis

Redis-backed distributed authentication rate limiting for Ashlar.

```csharp
services.AddAshlarRedisRateLimiting("localhost:6379", options =>
{
    options.KeyPrefix = "my-app:ashlar:rate-limits";
});
```

This package only provides `IAuthenticationRateLimiter` and rate limiter diagnostics. It does not add sessions, caching, pub/sub, or broader Redis infrastructure.
