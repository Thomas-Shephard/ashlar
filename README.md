# Ashlar
Building blocks for modern ASP.NET applications. Includes generic auth, security, and utility components.

## Persistence
Ashlar does not register persistence by default. The following official packages are available:

- **[Ashlar.Postgres](src/Ashlar.Postgres/README.md)**: PostgreSQL 15+ identity and session persistence using Dapper and DbUp.

## Identity DI Setup
Ashlar provides `IServiceCollection` extensions for registering its core identity services:

```csharp
// 1. Register persistence (e.g., PostgreSQL)
services.AddAshlarPostgres(connectionString);

// 2. Register secret protection
services.AddDataProtection();
services.AddAshlarDataProtectionSecretProtector();

// 3. Register core identity services
services.AddAshlarIdentity(
    options =>
    {
        options.LastUsedAtUpdateThreshold = TimeSpan.FromMinutes(5);
    },
    sessionOptions =>
    {
        sessionOptions.DefaultLifetime = TimeSpan.FromDays(14);
        sessionOptions.LastSeenUpdateThreshold = TimeSpan.FromMinutes(5);
        sessionOptions.TokenByteLength = 32;
        sessionOptions.StoreIpAddress = true;
        sessionOptions.StoreUserAgent = true;
        sessionOptions.StoreMetadata = true;
        sessionOptions.MaxIpAddressLength = 45;
        sessionOptions.MaxUserAgentLength = 512;
        sessionOptions.MaxMetadataLength = 8192;
    });

// 4. Register providers and hashers
services
    .AddAuthenticationProvider<LocalPasswordProvider>()
    .AddPasswordHasher<PasswordHasherV1>();
```

Applications must provide an `IIdentityRepository` implementation (either by using an official package above or a custom one).

Applications must also provide secret protection. For ASP.NET Core Data Protection, register Data Protection and call `AddAshlarDataProtectionSecretProtector()`. Ashlar does not use an insecure fallback protector.

Ashlar models durable authentication sessions through `AuthenticationSession`, `IAuthenticationSessionRepository`, and `IAuthenticationSessionService`.
The session service generates high-entropy raw tokens, hashes them before persistence, updates last-seen timestamps, and revokes sessions. Raw tokens are returned only once from `CreateSessionAsync`; `AuthenticationSession` stores only the deterministic token hash. HTTP cookies and ASP.NET authentication middleware are separate integration layers.

When supplied to `CreateSessionAsync`, session IP address, user agent, and metadata are persisted by default. These values can contain personal data, so applications should only pass them when their privacy policy and security requirements allow it. Use `AuthenticationSessionOptions.StoreIpAddress`, `StoreUserAgent`, and `StoreMetadata` to opt out, and tune the max-length options if the defaults do not fit your storage policy.

```csharp
var createResult = await sessionService.CreateSessionAsync(
    authenticationResult.User!.Id,
    new CreateAuthenticationSessionRequest(
        IpAddress: ipAddress,
        UserAgent: userAgent));

var rawToken = createResult.Token;

var validation = await sessionService.ValidateSessionAsync(rawTokenFromRequest);
if (validation.Succeeded)
{
    var userId = validation.UserId!.Value;
}

await sessionService.RevokeSessionAsync(createResult.Session.Id, "signed-out");
```

## Contributions
Contributions are welcome! Read the [contributing guide](CONTRIBUTING.md) to get started.

## License
This project is licensed under the [MIT License](LICENSE).
