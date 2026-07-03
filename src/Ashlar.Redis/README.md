# Ashlar.Redis

Redis-backed distributed authentication rate limiting for Ashlar.

```csharp
services.AddAshlarRedisRateLimiting("localhost:6379", options =>
{
    options.KeyPrefix = "my-app:ashlar:rate-limits";
});
```

`KeyPrefix` is required. Use an application-specific prefix when a Redis database is shared so rate-limit buckets from different applications cannot collide. Prefixes may contain ASCII letters, digits, `:`, `.`, `_`, and `-`; trailing colons are normalized away.

The shared prefix `ashlar:rate-limits` is no longer valid; existing Redis users must choose an application-specific prefix, and buckets stored under the old shared prefix will not be reused.

This package only provides `IAuthenticationRateLimiter`, rate limiter diagnostics, and safe rate-limit administration operations. It does not add sessions, caching, pub/sub, or broader Redis infrastructure.
