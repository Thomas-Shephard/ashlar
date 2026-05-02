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

## ASP.NET Core Session Cookies
Use **Ashlar.AspNetCore** to authenticate Ashlar sessions through the normal ASP.NET Core authentication middleware:

```csharp
services.AddAshlarPostgres(connectionString);
services.AddDataProtection();
services.AddAshlarDataProtectionSecretProtector();
services.AddAshlarIdentity();

services.AddAshlarAspNetCoreSessions(options =>
{
    options.SchemeName = "Ashlar";
    options.CookieName = "__Host-Ashlar.Session";
    options.LoginPath = "/login";
    options.AccessDeniedPath = "/forbidden";
});

app.UseAuthentication();
app.UseAuthorization();
```

After a successful application login, create the backing Ashlar session and append the cookie:

```csharp
var signInManager = httpContext.RequestServices.GetRequiredService<IAshlarSignInManager>();

await signInManager.SignInAsync(
    httpContext,
    authenticationResult.User!.Id);
```

`AddAshlarAspNetCoreSessions` registers the `"Ashlar"` authentication scheme by default. The handler reads the configured cookie, validates it with `IAuthenticationSessionService`, and creates an authenticated `ClaimsPrincipal` containing `ClaimTypes.NameIdentifier`, the Ashlar session id claim, and the authentication method claim.

Cookie defaults are intentionally secure: `HttpOnly = true`, `SecurePolicy = Always`, `SameSite = Lax`, and `Path = "/"`. `SameSite=Lax` is chosen so normal top-level navigation back to an application login flow keeps working while cross-site subresource and background requests do not carry the session cookie. Applications that need stricter same-site behavior can configure the cookie builder.

## Security Audit Events
Ashlar emits structured security audit events for authentication, credential lifecycle, and session lifecycle operations. `AddAshlarIdentity()` registers `ISecurityEventSink` with `NullSecurityEventSink` by default, so events are no-op unless the application provides a sink:

```csharp
services.AddSingleton<ISecurityEventSink, MySecurityEventSink>();
services.AddAshlarIdentity();
```

Event payloads include stable event types, timestamps, user/session ids when known, provider identity, IP address, user agent, correlation id, outcome, failure reason, and string properties. Audit events must not contain raw session tokens, passwords, one-time codes, credential values, or other secrets.

## Contributions
Contributions are welcome! Read the [contributing guide](CONTRIBUTING.md) to get started.

## License
This project is licensed under the [MIT License](LICENSE).
