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

Session token generation and hashing use the reusable `Ashlar.Security.Tokens` primitives registered by `AddAshlarIdentity()`: `ISecureTokenGenerator` with `SecureTokenGenerator`, and `ISecureTokenHasher` with `Sha256TokenHasher`. These primitives are intended for high-entropy server-generated tokens such as sessions, magic links, password reset links, and future challenge tokens. They are separate from `IPasswordHasher` and `PasswordHasherV1`, which remain for low-entropy user-chosen passwords.

`SecureTokenGenerator` generates Base64Url tokens from 32 to 192 random bytes. The upper bound keeps generated tokens compatible with the default `Sha256TokenHasher` input limit. Existing code that customized the old session-specific token generator or hasher should register `ISecureTokenGenerator` or `ISecureTokenHasher` instead.

## Messaging
Ashlar includes a framework-neutral email abstraction for identity and security flows that need to send or queue email messages, such as passwordless email sign-in, password reset, MFA recovery, and security notifications.

The abstraction lives in `Ashlar.Messaging`, not `Ashlar.Identity`, so authentication providers can depend on message creation without coupling to SMTP, a cloud email vendor, ASP.NET Core, or a persistence outbox.

`AddAshlarIdentity()` calls `AddAshlarMessaging()` and registers `IEmailSender` with `NullEmailSender` by default. `NullEmailSender` accepts valid `EmailMessage` instances and sends nothing, which keeps the core library usable and test-friendly without choosing an email delivery provider.

Applications should replace the default sender with their own implementation before calling `AddAshlarIdentity()` or `AddAshlarMessaging()`:

```csharp
services.AddSingleton<IEmailSender, MyEmailSender>();
services.AddAshlarIdentity();
```

`EmailMessage` contains simple string address fields (`To`, `From`, and `ReplyTo`) plus subject, text and/or HTML body, headers, and metadata. Ashlar intentionally does not implement SMTP, vendor integrations, templates, MIME parsing, address-list handling, or outbox persistence in the core abstraction.

## Passwordless Email Sign-In
Ashlar includes framework-neutral passwordless email sign-in services for one-time codes and magic links. Both flows use `IEmailSender`, `IAuthenticationRateLimiter`, `ISecureTokenGenerator`, and `ISecureTokenHasher`, so applications should replace the default `NullEmailSender` before using them in production.

Register magic-link sign-in with core identity services:

```csharp
services.AddSingleton<IEmailSender, MyEmailSender>();

services.AddAshlarMagicLinkSignIn(options =>
{
    options.LinkLifetime = TimeSpan.FromMinutes(10);
    options.LinkTokenParameterName = "token";
    options.EmailSubject = "Sign in";
    options.EmailTextTemplate = "Click the following link to sign in: {0}";
});
```

Request a link for an active user, then verify the raw token from the callback URL:

```csharp
var magicLinks = httpContext.RequestServices.GetRequiredService<IMagicLinkSignInService>();

await magicLinks.RequestLinkAsync(
    email,
    new Uri("https://app.example.com/auth/magic-link/callback"),
    new AuthenticationContext(
        IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
        UserAgent: httpContext.Request.Headers.UserAgent.ToString()));

var token = httpContext.Request.Query["token"].ToString();
var authenticationResult = await magicLinks.VerifyLinkAsync(
    token,
    new AuthenticationContext(
        IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
        UserAgent: httpContext.Request.Headers.UserAgent.ToString()));
```

`RequestLinkAsync` does not reveal whether an email address belongs to an active user. Generated links are stored as hashed credentials, expire according to `LinkLifetime`, and the default request and verification rate limits can be changed through `MagicLinkSignInOptions`.

One-time email codes are available through `AddAshlarEmailCodeSignIn()` and `IEmailCodeSignInService`:

```csharp
services.AddAshlarEmailCodeSignIn();

await emailCodes.RequestCodeAsync(email, context);
var authenticationResult = await emailCodes.VerifyCodeAsync(email, code, context);
```

## Recovery Codes
Ashlar includes a framework-neutral service for generating and verifying backup recovery codes. These are typically used as a fallback authentication method when a user loses access to their primary multi-factor authentication device.

Register recovery codes with core identity services:

```csharp
services.AddAshlarRecoveryCodes(options =>
{
    options.CodeCount = 10;
    options.CodeLength = 12;
    options.GroupSize = 4; // Generates codes like XXXX-XXXX-XXXX
});
```

To generate and retrieve the raw recovery codes for a user:

```csharp
var recoveryCodes = httpContext.RequestServices.GetRequiredService<IRecoveryCodeService>();

// Generates new codes. Any existing codes are revoked.
var rawCodes = await recoveryCodes.GenerateRecoveryCodesAsync(userId);
```

To verify a recovery code during sign-in, use the standard `AuthenticationPipeline` with a `RecoveryCodeAssertion`:

```csharp
var pipeline = httpContext.RequestServices.GetRequiredService<IAuthenticationPipeline>();

var assertion = new RecoveryCodeAssertion(
    code: userInputCode,
    ipAddress: httpContext.Connection.RemoteIpAddress?.ToString());

var authenticationResponse = await pipeline.LoginAsync(
    new AuthenticationContext(Email: userEmail), 
    assertion);

if (authenticationResponse.Succeeded)
{
    // The recovery code was valid and has been automatically consumed
}
```

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

## Rate Limiting
Ashlar includes framework-neutral rate limiting primitives to protect sensitive authentication flows. `AddAshlarIdentity` registers a thread-safe `InMemoryAuthenticationRateLimiter` by default. 

**Note**: The default in-memory rate limiter is suitable for development and single-instance deployments. Distributed production applications should implement and register a persistent/distributed `IAuthenticationRateLimiter`.

The **Ashlar.Postgres** package includes a PostgreSQL-backed implementation that uses row-level locking for atomic distributed limiting. Register it using:

```csharp
services.AddAshlarPostgres(connectionString);
services.AddAshlarPostgresRateLimiting(options =>
{
    options.CleanupInterval = TimeSpan.FromMinutes(5);
    options.MaxCleanupRows = 1000;
});
```

The PostgreSQL implementation uses the same schema initialized by `InitializeAshlarPostgresSchemaAsync()`. It supports opportunistic cleanup of expired entries during active rate limit checks.

Callers should choose rate limit keys carefully (e.g., per-email, per-IP, or composite keys) to isolate flows correctly.

## Transactions
Ashlar supports scoped database transactions through the `IAshlarTransactionProvider` abstraction. This allows multiple repository operations within a single service scope to participate in a shared unit of work.

```csharp
public class MyIdentityService(
    IIdentityService identityService, 
    IAshlarTransactionProvider transactionProvider)
{
    public async Task RegisterAndInviteAsync(User user)
    {
        // Start a transaction for the current scope
        await using var transaction = await transactionProvider.BeginTransactionAsync();
        
        try
        {
            await identityService.CreateUserAsync(user);
            await identityService.SetPasswordAsync(user.Id, "...");
            
            // All operations in this scope now share the same transaction
            await transaction.CommitAsync();
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }
}
```

`AddAshlarIdentity()` registers a `NullTransactionProvider` by default, which performs no-op transactions. Persistence packages like **Ashlar.Postgres** provide a functional implementation.

- **Scope Bound**: Transactions are bound to the `IServiceProvider` scope (typically the HTTP request).
- **Single Transaction**: Only one active transaction is supported per scope. Attempting to start a nested transaction will throw an `InvalidOperationException`.
- **Resource Management**: Callers MUST call `DisposeAsync` (typically via `await using`) to release the underlying connection, even after a commit or rollback.

## Security Audit Events
Ashlar emits structured security audit events for authentication, credential lifecycle, and session lifecycle operations. `AddAshlarIdentity()` registers `ISecurityEventSink` with `NullSecurityEventSink` by default, so events are no-op unless the application provides a sink:

```csharp
services.AddSingleton<ISecurityEventSink, MySecurityEventSink>();
services.AddAshlarIdentity();
```

Audit event payloads include stable event types, timestamps, user/session ids when known, provider identity, IP address, user agent, correlation id, outcome, failure reason, and string properties. Audit events must not contain raw session tokens, passwords, one-time codes, credential values, or other secrets.

The **Ashlar.Postgres** package includes a PostgreSQL-backed sink:

```csharp
services.AddAshlarPostgres(connectionString);
services.AddAshlarPostgresAuditSink();
```


## Contributions
Contributions are welcome! Read the [contributing guide](CONTRIBUTING.md) to get started.

## License
This project is licensed under the [MIT License](LICENSE).
