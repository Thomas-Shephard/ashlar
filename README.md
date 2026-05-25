# Ashlar
Building blocks for modern ASP.NET applications. Includes generic auth, security, and utility components.

## Reference Sample

A small ASP.NET Core reference app is available at [samples/Ashlar.Sample.AspNetCore](samples/Ashlar.Sample.AspNetCore/README.md). It shows the recommended composition for PostgreSQL persistence, Data Protection secret protection, Ashlar session cookies, magic-link and email-code sign-in, passkeys, invitation registration, optional Google OIDC sign-in/linking/unlinking, authorization grants, scoped ASP.NET Core policies, TOTP MFA, recovery codes, the PostgreSQL email outbox, cleanup, audit sink, and rate limiting.

## Persistence
Ashlar does not register persistence by default. The following official packages are available:

- **[Ashlar.Postgres](src/Ashlar.Postgres/README.md)**: PostgreSQL 15+ identity and session persistence using Dapper and DbUp.
- **[Ashlar.Sqlite](src/Ashlar.Sqlite/README.md)**: SQLite persistence infrastructure for single-instance self-hosted deployments, including identity repositories, sessions, authorization grants, auditing, rate limiting, email outbox, cleanup, schema management, and transactions.
- **[Ashlar.Passkeys](src/Ashlar.Passkeys/README.md)**: Optional WebAuthn/FIDO2 passkey provider and ceremony services. The package includes the default Fido2-backed ceremony validator and can be replaced with a custom `IPasskeyCeremonyValidator`.

## Passkeys / WebAuthn

Passkey/WebAuthn support is provided by the optional `Ashlar.Passkeys` package. It registers a passkey authentication provider and `IPasskeyService` while keeping WebAuthn/FIDO2 dependencies out of core Ashlar.

Configure the relying party id, relying party name, and HTTPS production origin before enabling browser flows. Loopback and `localhost` HTTP origins are allowed for local development where browsers treat them as secure contexts. Registered passkeys are stored as normal Ashlar credentials with `ProviderType.Passkey`; ceremony challenges are short-lived, purpose-scoped, origin/RP-scoped, and single-use. Public sign-in should use discoverable credentials without an email allow-list. Trusted reauthentication or step-up flows can start challenges scoped to a known `UserId`.

Passkeys participate in Ashlar's MFA-aware authentication orchestration for primary sign-in, so configured MFA policies still apply before an ASP.NET Core session is issued. A passkey is always listed as a passkey in account posture; applications should only describe it as satisfying additional verification when the active policy allows the `passkey` factor.

## Identity DI Setup
Ashlar provides `IServiceCollection` extensions for registering its core identity services:

```csharp
// 1. Register persistence (e.g., PostgreSQL)
services.AddAshlarPostgres(connectionString);

// 2. Register secret protection required by credential features that store protected secrets
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

Applications must provide `IUserRepository` and `ICredentialRepository` implementations (either by using an official package above or custom ones).

Applications must also provide secret protection before using credential features that store or read protected secrets, such as TOTP shared secrets, recovery credentials, and email-change secrets. Core Ashlar owns the `ISecretProtector` abstraction but does not ship a default implementation. ASP.NET Core Data Protection integration is provided by `Ashlar.AspNetCore`; register Data Protection and call `AddAshlarDataProtectionSecretProtector()` from the ASP.NET Core package. Ashlar does not use an insecure fallback protector.

Ashlar models durable authentication sessions through `AuthenticationSession`, `IAuthenticationSessionRepository`, and `IAuthenticationSessionService`.
The session service generates high-entropy raw tokens, hashes them before persistence, updates last-seen timestamps, and revokes sessions. Raw tokens are returned only once from `CreateSessionAsync`; `AuthenticationSession` stores only the deterministic token hash. Sessions can also carry safe authentication metadata such as authentication time, primary provider, and recent additional verification provider/factor. This metadata intentionally excludes raw tokens, one-time codes, passkey ceremony payloads, recovery codes, password hashes, and protected secrets. Last-seen updates are advisory and must not make revoked or expired sessions active again. HTTP cookies and ASP.NET authentication middleware are separate integration layers.

Session token generation and hashing use the reusable `Ashlar.Security.Tokens` primitives registered by `AddAshlarIdentity()`: `ISecureTokenGenerator` with `SecureTokenGenerator`, and `ISecureTokenHasher` with `Sha256TokenHasher`. These primitives are intended for high-entropy server-generated tokens such as sessions, magic links, password reset links, and future challenge tokens. They are separate from `IPasswordHasher` and `PasswordHasherV1`, which remain for low-entropy user-chosen passwords.

`SecureTokenGenerator` generates Base64Url tokens from 32 to 192 random bytes. The upper bound keeps generated tokens compatible with the default `Sha256TokenHasher` input limit. Existing code that customized the old session-specific token generator or hasher should register `ISecureTokenGenerator` or `ISecureTokenHasher` instead.

## Callback URI Validation
Ashlar validates token-bearing callback bases through `IUriValidator` before generating links for magic-link sign-in, invitations, email verification, and email change. Configure trusted public application roots or callback paths with `UriValidationOptions.AllowedCallbackUris`:

```csharp
services.Configure<UriValidationOptions>(options =>
{
    options.AllowedCallbackUris.Add("https://app.example.com");
    options.AllowedCallbackUris.Add("https://admin.example.com/invitations");
});
```

Allowed entries must be absolute `https` or `http` URIs without query strings or fragments. Candidate callback bases must use the same scheme, host, and port, and their path must match exactly or be under the allowed path on a path-segment boundary. For example, allowing `https://app.example.com/app` permits `/app` and `/app/callback`, but not `/app2`. Allowing `https://app.example.com` permits only the root callback path; add each trusted callback path explicitly.

Use `https` in production. For local development, explicitly allow the loopback HTTP origin you run, such as `http://localhost:5000`, and avoid modeling production with arbitrary callback URLs from user input. Ashlar appends token query parameters after validation; do not include query strings or fragments in callback bases.

## Request Contexts
Ashlar keeps runtime context split by responsibility. Use `AuthenticationContext` for authentication attempts and authentication-provider lookup metadata: email, tenant scope, IP address, user agent, correlation id, return URL, and non-secret items. Use `AuditContext` for non-authentication operations that still need security audit metadata, such as email verification and email change requests. Tenant-aware apps pass the same tenant id into `AuthenticationContext.TenantId`, invitation/bootstrap request `TenantId`, and authorization grant/evaluation `TenantId`; omitting the tenant means global scope, not a cross-tenant lookup.

```csharp
var authContext = new AuthenticationContext(
    Email: email,
    TenantId: tenantId,
    IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
    UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
    CorrelationId: httpContext.TraceIdentifier);

var auditContext = new AuditContext(
    ActorUserId: currentUserId,
    IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
    UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
    CorrelationId: httpContext.TraceIdentifier);
```

Ashlar deliberately does not store or expose raw passwords, password hashes, raw session tokens, magic-link tokens, email verification/change tokens, recovery codes, protected payloads, or other secret credential values in context or audit payloads.

Credential provider keys are ownership-bound. Repository implementations must not resolve a provider-key conflict by moving an existing credential to another user; link operations may replace credential material for the same user and provider identity, but cross-user ownership changes must fail closed.

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

`RequestLinkAsync` does not reveal whether an email address belongs to an active user. Generated links are stored as hashed credentials, expire according to `LinkLifetime`, and the default request and verification rate limits can be changed through `MagicLinkSignInOptions`. Successful magic-link and email-code assertions consume their backing credential so the same token or code cannot be replayed.

One-time email codes are available through `AddAshlarEmailCodeSignIn()` and `IEmailCodeSignInService`:

```csharp
services.AddAshlarEmailCodeSignIn();

await emailCodes.RequestCodeAsync(email, context);
var authenticationResult = await emailCodes.VerifyCodeAsync(email, code, context);
```

## Email Verification
Ashlar includes services for verifying user email addresses. This is typically used during onboarding or after an email change.

Register email verification services:

```csharp
services.AddAshlarEmailVerification(options =>
{
    options.Expiration = TimeSpan.FromHours(24);
    options.Subject = "Verify your email address";
});
```

Request verification for a user:

```csharp
var verificationService = httpContext.RequestServices.GetRequiredService<IEmailVerificationService>();

await verificationService.RequestVerificationAsync(new EmailVerificationRequest
{
    UserId = userId,
    CallbackBaseUri = new Uri("https://app.example.com/account/verify-email"),
    Audit = auditContext
});
```

Verify the token (e.g., from a link in the email):

```csharp
var result = await verificationService.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest
{
    UserId = userId,
    Token = tokenFromUrl,
    Audit = auditContext
});

if (result.Succeeded)
{
    // Email is now marked as verified (user.EmailVerifiedAt is set)
}
```

When a service returns `Result` or `Result<T>`, branch on the stable failure code rather than parsing the display message:

```csharp
var result = await verificationService.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest
{
    UserId = userId,
    Token = tokenFromUrl,
    Audit = auditContext
});

if (!result.Succeeded)
{
    if (result.FailureCode == AshlarFailureCodes.InvalidOrExpiredToken)
    {
        return Results.BadRequest(new { error = "The verification link is invalid or expired." });
    }

    return Results.BadRequest(new
    {
        code = result.FailureCode?.Value,
        message = result.FailureMessage ?? "The request could not be completed."
    });
}
```

`FailureCode` is the stable, machine-readable value. `FailureMessage` and `FailureReason` are for display/logging and may be deliberately generic to avoid leaking sensitive details.

## Email Change
Ashlar supports a secure two-step email change flow that verifies ownership of the new email address before updating the user record.

Register email change services:

```csharp
services.AddAshlarEmailChange(options =>
{
    options.Expiration = TimeSpan.FromHours(2);
    options.Subject = "Confirm your new email address";
    options.RevokeSessions = true; // Optional: revoke all user sessions after change
});
```

Email-change tokens are stored as hashed provider keys and bind to the requesting user. The pending new email is protected at rest until confirmation. When `RevokeSessions` is enabled with the official PostgreSQL persistence package, existing sessions are revoked in the same persistence transaction as the email update before success events and notifications are emitted. Custom persistence implementations should use the same transaction boundary for identity and session repositories to preserve that guarantee.

Step 1: Request an email change:

```csharp
var emailChangeService = httpContext.RequestServices.GetRequiredService<IEmailChangeService>();

var result = await emailChangeService.RequestChangeAsync(new RequestEmailChangeRequest
{
    UserId = userId,
    NewEmail = "new-email@example.com"
});
```

Step 2: Confirm the change using the token sent to the NEW email:

```csharp
var result = await emailChangeService.ConfirmChangeAsync(new ConfirmEmailChangeRequest
{
    UserId = userId,
    Token = tokenFromNewEmail
});

if (result.Succeeded)
{
    // User email has been updated and marked as verified
}
```

Email change requests are automatically throttled, and the process ensures that the new email is not already in use by another user in the same tenant.

## Password Reset
Ashlar supports first-class password reset for local password credentials through `AddAshlarPasswordReset()` and `IPasswordResetService`.

Register password reset with core identity, a local password hasher, callback URI validation, an email sender, and persistence for users, credentials, and sessions:

```csharp
services.AddAshlarPostgres(connectionString);
services.AddSingleton<IEmailSender, MyEmailSender>();

services.Configure<UriValidationOptions>(options =>
{
    options.AllowedCallbackUris.Add("https://app.example.com/account/reset-password");
});

services
    .AddAshlarIdentity()
    .AddAuthenticationProvider<LocalPasswordProvider>()
    .AddPasswordHasher<PasswordHasherV1>();

services.AddAshlarPasswordReset(options =>
{
    options.Expiration = TimeSpan.FromHours(2);
    options.RevokeSessions = true;
    options.MinimumRequestDuration = TimeSpan.FromMilliseconds(250);
});
```

`AddAshlarIdentity()` registers the default `IUriValidator`, in-memory `IAuthenticationRateLimiter`, secure token generator/hasher, and null email sender. Production applications should replace the null email sender and use durable/distributed persistence and rate limiting when running more than one instance. Password reset also requires `IUserRepository`, `ICredentialRepository`, and `IAuthenticationSessionRepository`; official persistence packages provide these repositories.

Request a reset email without revealing whether the address exists, is disabled, or has a local password:

```csharp
var passwordReset = httpContext.RequestServices.GetRequiredService<IPasswordResetService>();

await passwordReset.RequestPasswordResetAsync(
    email,
    new Uri("https://app.example.com/account/reset-password"),
    new AuthenticationContext(
        TenantId: tenantId,
        IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
        UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
        CorrelationId: httpContext.TraceIdentifier));
```

Complete the reset with the raw token from the callback URL and the replacement password:

```csharp
var result = await passwordReset.ResetPasswordAsync(
    new PasswordResetRequest
    {
        Token = tokenFromUrl,
        NewPassword = newPassword
    },
    new AuthenticationContext(
        TenantId: tenantId,
        IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
        UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
        CorrelationId: httpContext.TraceIdentifier));

if (!result.Succeeded && result.FailureCode == AshlarFailureCodes.InvalidOrExpiredToken)
{
    return Results.BadRequest(new { error = "The reset link is invalid or expired." });
}
```

Reset tokens are high-entropy generated tokens stored only as `ISecureTokenHasher` hashes in internal password-reset credentials. The new password is stored through the normal local password hashing path. Successful reset consumes the reset token, replaces existing local password credentials, revokes existing sessions by default, emits security audit events, and sends a post-reset security notification when security notifications are configured.

## TOTP Authenticator
Ashlar includes a framework-neutral service for managing and verifying TOTP (Time-based One-Time Password) authenticator factors. These are standard RFC 6238 codes compatible with apps like Google Authenticator, Microsoft Authenticator, and 1Password.

Register TOTP with core identity services:

```csharp
services.AddAshlarTotp(options =>
{
    options.CodeDigits = 6;
    options.StepSeconds = 30;
});
```

### Enrollment
To enroll a user, generate a new shared secret and an authenticator URI:

```csharp
// 1. Start enrollment (totpService is ITotpService)
var enrollment = await totpService.StartEnrollmentAsync(userId, "Ashlar", "user@example.com");

// 2. Return enrollment.AuthenticatorUri to the client for QR code generation.
// 3. Keep enrollment.SharedSecret temporarily to verify the first code.
```

The user must verify a code from their authenticator app to finalize enrollment:

```csharp
// 4. Verify first code and finalize enrollment
bool success = await totpService.VerifyAndEnrollAsync(userId, sharedSecret, userInputCode);
```

`VerifyAndEnrollAsync` replaces any existing TOTP credential for the user and stores the new secret as a protected credential value.

### Verification
To verify a TOTP code during sign-in, use the standard `AuthenticationPipeline` or `AuthenticationOrchestrator` with a `TotpAssertion`:

```csharp
var orchestrator = httpContext.RequestServices.GetRequiredService<IAuthenticationOrchestrator>();

var result = await orchestrator.VerifyFactorAsync(
    handshakeToken,
    "totp",
    new AuthenticationContext(IpAddress: ip),
    new TotpAssertion(userInputCode));

if (result.Status == MfaAuthenticationStatus.Succeeded)
{
    // TOTP verified!
}
```

### Management
To disable TOTP for a user:

```csharp
await totpService.DisableTotpAsync(userId);
```

TOTP verification is automatically throttled by `IAuthenticationRateLimiter` to protect against brute-force attacks. Shared secrets are never stored in raw form; they are always encrypted using `ISecretProtector`.

## Invitations
Ashlar includes a generic invitation and onboarding flow that supports inviting users by email address, even when they do not yet exist in the system.

Register invitation services:

```csharp
services.AddAshlarInvitations(options =>
{
    options.DefaultExpiry = TimeSpan.FromDays(7);
    options.EmailSubject = "You're invited!";
    options.EmailTextTemplate = "Join us here: {0}";
});
```

Create an invitation:

```csharp
var invitations = httpContext.RequestServices.GetRequiredService<IInvitationService>();

await invitations.CreateInvitationAsync(
    new CreateInvitationRequest
    {
        Email = "invitee@example.com",
        Metadata = "{\"role\": \"editor\"}"
    },
    new Uri("https://app.example.com/join"));
```

Accept an invitation:

```csharp
var result = await invitations.AcceptInvitationAsync(
    new AcceptInvitationRequest
    {
        Token = tokenFromUrl,
        UserName = "Jane Doe"
    });

if (result.Succeeded)
{
    var userId = result.Value;
}
```

`CreateInvitationAsync` generates a high-entropy token, stores its hash, and sends an invitation link via `IEmailSender`. When an invitation is accepted, Ashlar automatically creates a new active user if one does not exist, or activates/links an existing inactive user. Acceptance is atomic and single-use. PostgreSQL acceptance updates require the invitation to still be unaccepted, unrevoked, and unexpired at write time, so stale reads cannot replay or revive an invitation.

## Bootstrap and First-Admin Setup
Ashlar includes generic bootstrap primitives that allow a newly self-hosted application to safely create its first administrative user without manual database edits.

Register bootstrap services:

```csharp
services.AddAshlarBootstrap(options =>
{
    options.Grants.Add(new BootstrapGrantTemplate
    {
        Role = "admin"
    });
});
```

Check bootstrap status and create the first-admin invitation:

```csharp
var bootstrap = httpContext.RequestServices.GetRequiredService<IBootstrapService>();

if (await bootstrap.GetStatusAsync() == BootstrapStatus.Uninitialized)
{
    var result = await bootstrap.CreateBootstrapInvitationAsync(new CreateBootstrapInvitationRequest
    {
        Email = "admin@example.com"
    });

    if (result.Succeeded)
    {
        // Display result.Token to the administrator
    }
}
```

Accept the bootstrap invitation:

```csharp
var result = await bootstrap.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest
{
    Token = tokenFromUrl,
    UserName = "Admin User"
});

if (result.Succeeded)
{
    // The system is now initialized and the user has 'admin' role.
}
```

Bootstrap is available only while the application is uninitialized. Initialization is determined by a persistent marker in the database. Accepting a bootstrap invitation is atomic, single-use, and assigns all configured grants to the new user before marking the system as initialized.

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
using Ashlar.Identity.Providers.RecoveryCode;

var recoveryCodes = httpContext.RequestServices.GetRequiredService<IRecoveryCodeService>();

// Generates new codes. Any existing codes are revoked.
var rawCodes = await recoveryCodes.GenerateRecoveryCodesAsync(userId);
```

To verify a recovery code during sign-in, use the standard `AuthenticationPipeline` with a `RecoveryCodeAssertion`:

```csharp
using Ashlar.Identity.Providers.RecoveryCode;

var pipeline = httpContext.RequestServices.GetRequiredService<IAuthenticationPipeline>();

var assertion = new RecoveryCodeAssertion(userInputCode);

var authenticationResponse = await pipeline.LoginAsync(
    new AuthenticationContext(
        Email: userEmail,
        IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
        UserAgent: httpContext.Request.Headers.UserAgent.ToString()),
    assertion);

if (authenticationResponse.Succeeded)
{
    // The recovery code was valid and has been automatically consumed
}
```

## MFA Policy and Orchestration
Ashlar provides a high-level orchestration layer that connects primary authentication to MFA policy enforcement and handshake management. This allows applications to define generic MFA requirements and manage the multi-step verification process.

Register the orchestration services:

```csharp
services.AddAshlarMfaOrchestration();
```

By default, Ashlar registers a no-MFA policy. Primary authentication can complete without a handshake unless an authentication provider itself returns `AuthenticationStatus.MfaRequired` or an application explicitly registers a policy:

```csharp
services.AddAshlarMfaOrchestration();
// Equivalent explicit policy:
services.AddAshlarNoMfaPolicy();
```

To require TOTP only for users who already have an active TOTP credential, register a credential-backed policy:

```csharp
services
    .AddAshlarTotp()
    .AddAshlarRequireMfaWhenCredentialExists(options =>
    {
        options.CredentialProviderKeys.Add(new AuthenticationProviderKey(ProviderType.Mfa, "totp"));
        options.RequiredFactors.Add("totp");
    });
```

The credential-backed policy checks configured provider identities only. It uses active, non-revoked, non-expired credentials and does not inspect credential values.

To require MFA for every active user:

```csharp
services.AddAshlarRequireMfaForAllUsers(options =>
{
    options.RequiredFactors.Add("totp");
});
```

Perform a primary authentication that might require MFA:

```csharp
var orchestrator = httpContext.RequestServices.GetRequiredService<IAuthenticationOrchestrator>();

var result = await orchestrator.AuthenticateAsync(
    new AuthenticationContext(IpAddress: ip),
    new LocalPasswordAssertion(email, password));

if (result.Status == MfaAuthenticationStatus.MfaRequired)
{
    // Primary auth succeeded, but MFA is required.
    // Send the raw continuation token and required factors to the client.
    return Results.Ok(new {
        token = result.HandshakeToken,
        factors = result.RequiredFactors
    });
}
```

Verify an additional factor using the continuation token:

```csharp
var result = await orchestrator.VerifyFactorAsync(
    tokenFromClient,
    "email_code",
    new AuthenticationContext(IpAddress: ip),
    new EmailCodeAssertion(code));

if (result.Status == MfaAuthenticationStatus.Succeeded)
{
    // All factors verified! Now create the session.
    await signInManager.SignInAsync(httpContext, result.User.Id);
}
```

The orchestrator ensures that factor verification happens through the same provider machinery as primary authentication. It also aggregates claims from all authentication steps into the final result.

## Multi-Factor Authentication (MFA) Handshakes
Ashlar includes a generic infrastructure for tracking multi-step authentication flows through "handshakes". This allows primary authentication (like passwords) to be verified while requiring additional factors before a final session is issued.

Register MFA handshake services:

```csharp
services.AddAshlarMfaHandshakes(options =>
{
    options.Expiry = TimeSpan.FromMinutes(15);
});
```

`AddAshlarMfaHandshakes()` registers the service layer only. Applications must also register an `IAuthenticationHandshakeRepository` implementation, such as by calling `AddAshlarPostgres(connectionString)`, or provide their own repository.

When a user's primary authentication succeeds but MFA is required, initiate a handshake:

```csharp
var handshakeService = httpContext.RequestServices.GetRequiredService<IAuthenticationHandshakeService>();

var createResult = await handshakeService.CreateHandshakeAsync(new CreateAuthenticationHandshakeRequest(
    userId,
    RequiredFactors: ["totp"]));

if (!createResult.Succeeded || createResult.Value == null)
{
    return Results.BadRequest(new { error = createResult.FailureCode?.Value });
}

// Return createResult.Value.Token to the client. It will be needed to verify factors.
```

Verify a factor to continue or complete the handshake:

```csharp
var result = await handshakeService.VerifyFactorAsync(new VerifyAuthenticationHandshakeRequest(
    tokenFromClient,
    "totp"));

if (result.Succeeded && result.Value is { IsCompleted: true } handshake)
{
    // All required factors verified! Create the final session.
    await signInManager.SignInAsync(httpContext, handshake.UserId);
}
```

Handshakes are time-limited, single-use, and stored as hashed continuation tokens. They track generic "factor types" allowing applications to implement any MFA method (TOTP, Email Code, Passkeys, etc.) and integrate them into a unified handshake flow.

Fresh MFA and step-up support is built from session authentication metadata plus the framework-neutral `IStepUpAuthenticationService`. The evaluator answers whether a session is active and has recent additional verification within a required freshness window, optionally constrained to allowed providers or factor names. After an already-authenticated user completes an additional verification factor, applications can mark the known current session fresh with `MarkVerifiedAsync` or `IAuthenticationSessionService.MarkStepUpVerifiedAsync` by passing the current session id, the verified provider, and a safe factor name such as `totp`, `recovery_code`, or `passkey`. This updates only an active session owned by that user and stores no raw codes, recovery codes, passkey ceremony JSON, tokens, password hashes, or protected payloads.

This step-up update is different from primary login and from login-time MFA handshakes that run before a session is issued. It is for refreshing an existing session before a sensitive action. Endpoint helpers, ASP.NET Core authorization policies, and challenge/completion UX are intentionally separate integration layers and are not required to use the core service.

ASP.NET Core apps can choose strict or conditional fresh MFA:

```csharp
services.AddAshlarAspNetCoreAuthorization(options =>
{
    options.StepUp.FreshnessWindow = TimeSpan.FromMinutes(10);
    options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Totp);
    options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.RecoveryCode);
    options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);

    options.RequireFreshMfa();
    options.RequireFreshMfaIfAvailable();
});

app.MapPost("/account/change-email", ChangeEmailAsync)
    .RequireFreshMfa();

app.MapDelete("/api/sessions/{id:guid}", RevokeSessionAsync)
    .RequireFreshMfaIfAvailable();
```

Use `.RequireFreshMfa()` for high-risk operations that must not proceed without recent additional verification. Use `.RequireFreshMfaIfAvailable()` for lower-risk sensitive operations where users with no usable eligible factor should not be locked out. Conditional mode loads `IAccountSecurityService.GetUserSecurityPostureAsync`, matches usable `AdditionalVerificationFactors` against the configured eligible factors, and requires the same fresh session verification only when at least one eligible factor is available. If posture cannot be loaded safely, authorization is denied. The default conditional policy treats `totp`, `recovery_code`, and `passkey` as eligible; applications can configure custom factor strings through `AshlarStepUpOptions.AllowedFactors`.

Conditional fresh MFA is weaker than strict fresh MFA because a user with no usable eligible factor is allowed through. It is an adaptive policy for lower-risk scenarios, not a replacement for strict step-up on administrator, recovery, credential reset, or other dangerous operations.

When supplied to `CreateSessionAsync`, session IP address, user agent, and metadata are persisted by default. These values can contain personal data, so applications should only pass them when their privacy policy and security requirements allow it. Use `AuthenticationSessionOptions.StoreIpAddress`, `StoreUserAgent`, and `StoreMetadata` to opt out, and tune the max-length options if the defaults do not fit your storage policy.

```csharp
var createResult = await sessionService.CreateSessionAsync(
    authenticationResult.User.Id,
    new CreateAuthenticationSessionRequest(
        IpAddress: ipAddress,
        UserAgent: userAgent));

var rawToken = createResult.Token;

var validation = await sessionService.ValidateSessionAsync(rawTokenFromRequest);
if (validation.Succeeded)
{
    var userId = validation.UserId.Value;
}

await sessionService.RevokeSessionAsync(createResult.Session.Id, "signed-out");
```

### Session and Device Management
Ashlar provides user-facing APIs for listing and revoking active sessions. This allows applications to build "Security" or "Devices" pages where users can see their active sessions and sign out of other devices.

#### Core Service API
Use `IAuthenticationSessionService` for low-level session management:

```csharp
// 1. List active sessions for a user
var request = new ListAuthenticationSessionsRequest
{
    ActiveOnly = true,
    CurrentSessionId = currentSessionId
};
var sessions = await sessionService.ListSessionsForUserAsync(userId, request);

foreach (var summary in sessions)
{
    // summary includes Id, CreatedAt, LastSeenAt, IpAddress, UserAgent, IsCurrent, etc.
}

// 2. Revoke a specific session (ownership is enforced)
await sessionService.RevokeSessionForUserAsync(userId, new RevokeAuthenticationSessionRequest
{
    SessionId = targetSessionId,
    Reason = "user-initiated"
});

// 3. Revoke all other sessions for a user
await sessionService.RevokeOtherSessionsAsync(userId, new RevokeOtherAuthenticationSessionsRequest
{
    CurrentSessionId = currentSessionId,
    Reason = "security-sweep"
});
```

#### ASP.NET Core Helpers
Use `IAshlarSignInManager` for simplified management of the currently authenticated user:

```csharp
// List sessions for the current user
var sessions = await signInManager.ListSessionsForCurrentUserAsync(httpContext);

// Revoke a specific session for the current user
await signInManager.RevokeSessionForCurrentUserAsync(httpContext, targetSessionId);

// Revoke all other sessions for the current user
await signInManager.RevokeOtherSessionsForCurrentUserAsync(httpContext);
```

Session listing is ordered by `CreatedAt` descending (newest first). Sensitive fields like IP address and user agent are only populated if they were enabled during session creation. Token hashes are never exposed through these APIs. In the PostgreSQL store, last-seen writes are ignored once a session is revoked or expired, so a concurrent sign-out or expiry cannot be undone by validation telemetry.

#### Admin Session Browsing
Use `IAuthenticationSessionAdministrationService` for read-only admin and operations tooling that needs to browse sessions across users and tenants without querying provider tables directly:

```csharp
var result = await sessionAdministration.SearchAuthenticationSessionsAsync(
    new SearchAuthenticationSessionsRequest
    {
        UserId = userId,
        Active = true,
        Limit = 50
    });

if (result.Succeeded)
{
    foreach (var session in result.Value.Items)
    {
        // session includes Id, UserId, TenantId, provider, timestamps, IpAddress, UserAgent, and IsActive.
    }
}
```

These APIs do not authorize callers. Host applications must enforce admin authorization, audit policy, and step-up requirements before exposing them. Raw session tokens and token hashes are never returned, and session metadata is not included in the admin read model.

#### Admin Credential Inventory
Use `ICredentialAdministrationService` for read-only admin and operations tooling that needs to browse credential inventory across users or tenants without querying provider tables directly:

```csharp
var result = await credentialAdministration.SearchCredentialsAsync(
    new SearchCredentialsRequest
    {
        UserId = userId,
        Provider = AuthenticationProviderKey.Passkey,
        Available = true,
        Limit = 50
    });

if (result.Succeeded)
{
    foreach (var credential in result.Value.Items)
    {
        // credential includes CredentialId, UserId, TenantId, Provider, Purpose, Status, timestamps, and IsAvailable.
    }
}
```

Call `GetCredentialAsync(credentialId)` for the same safe fields for a single credential. These APIs do not authorize callers. Host applications must enforce admin authorization, audit policy, and step-up requirements before exposing them. Raw credential values, provider keys, metadata, password hashes, token hashes, passkey payloads, recovery codes, OAuth/OIDC subject identifiers, provider-specific raw identifiers, and other secrets are never returned.

### Admin Account Recovery
Ashlar exposes framework-neutral administrator primitives through `IAccountSecurityService`. The service is intentionally small and composes existing identity, credential, MFA, recovery-code, session, and audit infrastructure.

Available operations:

- `DisableUserAsync`: marks the user inactive and revokes active sessions.
- `ReactivateUserAsync`: marks a disabled user active without changing credentials.
- `RevokeSessionsAsync`: revokes all active sessions for a user.
- `RevokeCredentialsAsync`: revokes active credentials for a specific provider key.
- `ResetMfaAsync`: revokes configured TOTP and recovery-code credentials.
- `GetUserSecurityPostureAsync`: returns a non-secret `AccountSecurityPosture` read model containing active state, email verification state, primary sign-in methods, additional verification factors, policy readiness, missing required factors, readable credential inventory, active session count, and recent security event count when the persistence provider supports it.

Account posture separates durable primary credentials from additional verification factors. Local passwords, external providers, email-code or magic-link sign-in credentials, and passkeys are primary sign-in methods. Authenticator apps are additional verification factors, recovery codes are backup additional verification factors, and passkeys can also be additional verification factors when policy or step-up requirements allow the `passkey` factor. One-time email sign-in credentials are not treated as durable MFA factors.

Applications should render `PrimaryCredentials`, `AdditionalVerificationFactors`, and `Policy` instead of formatting raw provider keys. Use the supplied display names such as "Password", "Email sign-in", "Authenticator app", "Recovery codes", and "Passkeys"; use `Policy.IsReadyForAdditionalVerification` and `Policy.MissingRequiredFactorDisplayNames` to explain whether the user can satisfy the current MFA or step-up policy. The posture inventory intentionally omits credential values, token hashes, public keys, passkey ceremony JSON, recovery codes, password hashes, and protected secrets.

Sensitive admin operations require `AccountSecurityOperationRequest` with an `AuditContext`. Applications are responsible for authorizing access before calling these methods, typically with an application admin role or scoped permission enforced by ASP.NET Core authorization. Ashlar records audit events with actor metadata, target user id, tenant id, reason, and affected counts; it does not return or log raw secrets, tokens, password hashes, recovery codes, protected payloads, or session tokens.

These primitives do not implement a full helpdesk workflow, admin UI, passkeys, OAuth, or OIDC. Applications can layer approval workflows, break-glass controls, and support tooling on top of the service.

## Authorization Grants
Ashlar includes framework-neutral authorization primitives for durable grants. Grants are generic: they can assign one normalized role or one normalized permission to a user, optionally within a tenant and explicit scope. Ashlar evaluates these grants, but it does not replace ASP.NET Core Authorization policies or requirements.

```csharp
services.AddAshlarAuthorization();
services.AddAshlarPostgres(connectionString);
```

Grant a permission:

```csharp
var grant = await grantService.CreateGrantAsync(new CreateAuthorizationGrantRequest(
    UserId: userId,
    Permission: "posts.edit"));
```

Grant a scoped role:

```csharp
await grantService.CreateGrantAsync(new CreateAuthorizationGrantRequest(
    UserId: userId,
    TenantId: tenantId,
    ScopeType: "project",
    ScopeId: projectId.ToString("D"),
    Role: "reviewer"));
```

Evaluate access:

```csharp
var result = await authorizationEvaluator.EvaluateAsync(new AuthorizationEvaluationRequest(
    UserId: userId,
    TenantId: tenantId,
    ScopeType: "project",
    ScopeId: projectId.ToString("D"),
    Permission: "posts.edit"));

if (!result.Succeeded)
{
    return Results.Forbid();
}
```

Scope matching is explicit. A scoped grant applies only when the evaluation request uses the same tenant, scope type, and scope id. A global grant is represented by omitting tenant and scope values.

### ASP.NET Core Authorization
Use **Ashlar.AspNetCore** to integrate Ashlar grants with standard ASP.NET Core authorization policies:

```csharp
services.AddAshlarAspNetCoreAuthorization(options =>
{
    // Global permission policy
    options.AddPermissionPolicy("PostsEdit", "posts.edit");

    // Scoped permission policy (resolves postId from route values)
    options.AddPermissionPolicy("ProjectMember", "project.member", scope =>
    {
        scope.ScopeType = "project";
        scope.ScopeIdRouteValueName = "projectId";
        scope.TenantIdSource = "tenantId"; // Optional: also resolve tenantId from route
    });

    // Role policy
    options.AddRolePolicy("Admin", "admin");
});
```

Use the registered policies in your controllers or minimal APIs:

```csharp
[Authorize(Policy = "PostsEdit")]
public IActionResult EditPost() => Ok();

[Authorize(Policy = "ProjectMember")]
[HttpGet("/projects/{projectId}/settings")]
public IActionResult ProjectSettings(Guid projectId) => Ok();
```

The integration automatically registers a `IAuthorizationHandler` that resolves the user ID from `ClaimTypes.NameIdentifier`, extracts scope/tenant data from route values as configured, and performs a live evaluation using `IAuthorizationEvaluator`. Scoped checks fail safely if the required route values are missing or invalid.

ASP.NET Core applications can also call `IAuthorizationEvaluator` directly from custom handlers for more complex logic. Avoid copying all grants into cookies unless you accept stale authorization until the cookie is refreshed.

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
    authenticationResult.User.Id);
```

`AddAshlarAspNetCoreSessions` registers the `"Ashlar"` authentication scheme by default. The handler reads the configured cookie, validates it with `IAuthenticationSessionService`, and creates an authenticated `ClaimsPrincipal` containing `ClaimTypes.NameIdentifier`, the Ashlar session id claim, the authentication method claim, safe session authentication metadata claims, and `AshlarClaimTypes.TenantId` when the session is tenant-scoped.

Cookie defaults are intentionally secure: `HttpOnly = true`, `SecurePolicy = Always`, `SameSite = Lax`, and `Path = "/"`. `SameSite=Lax` is chosen so normal top-level navigation back to an application login flow keeps working while cross-site subresource and background requests do not carry the session cookie. Applications that need stricter same-site behavior can configure the cookie builder.

## Rate Limiting
Ashlar includes framework-neutral rate limiting primitives to protect sensitive authentication flows. `AddAshlarIdentity` registers a thread-safe `InMemoryAuthenticationRateLimiter` by default.

**Note**: The default in-memory rate limiter is suitable for development and single-instance deployments. Distributed production applications should implement and register a persistent/distributed `IAuthenticationRateLimiter`.

If your rate limiting strategy depends on the client's IP address, you must protect your endpoints against requests where the IP address cannot be determined (which could bypass the rate limit). Ashlar provides the `UseAshlarRequireIpAddress` middleware for this purpose:

```csharp
// Returns a 400 Bad Request if the client IP is missing
app.UseAshlarRequireIpAddress();
```

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

Rate limiter diagnostics are available through `IAuthenticationRateLimiterDiagnostics` when Ashlar identity or a provider rate limiter is registered:

```csharp
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

var diagnostics = serviceProvider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>();
var result = await diagnostics.CheckAsync(cancellationToken);
```

The result reports `Status`, provider name, `CheckedAt`, whether the limiter is configured, distributed, and persistent, safe aggregate counts for expired rows, active keys, and blocked keys when the provider can query them, and cleanup scheduling settings when the provider exposes them. It returns `Healthy` when provider state can be queried, `NotSupported` when a provider table is missing or diagnostics are not available for a custom limiter, and `Unknown` when an unexpected provider query failure occurs. Diagnostics never expose rate-limit keys, purposes, IP addresses, subject identifiers, counters, or raw provider internals.

## Cleanup and Retention
Ashlar can explicitly remove expired or retained operational data from PostgreSQL: expired/revoked sessions and credentials, expired/accepted/revoked invitations, expired/completed/revoked MFA handshakes, expired/consumed passkey challenges, expired rate-limit rows, and old audit events. Audit-event retention is disabled by default and must be configured intentionally.

Register the cleanup service and call it from an administrative job or maintenance endpoint:

```csharp
services.AddAshlarPostgres(connectionString);
services.AddAshlarPostgresCleanup(options =>
{
    options.BatchSize = 500;
    options.MaxBatchesPerRun = 10;
    options.RemoveExpiredPasskeyChallengesAfter = TimeSpan.FromDays(1);
    options.RemoveConsumedPasskeyChallengesAfter = TimeSpan.FromDays(1);
    options.RemoveAuditEventsAfter = TimeSpan.FromDays(365);
});
```

```csharp
public sealed class MaintenanceJob(IServiceScopeFactory scopeFactory)
{
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var cleanup = scope.ServiceProvider.GetRequiredService<IAshlarCleanupService>();

        AshlarCleanupResult result = await cleanup.CleanupAsync(cancellationToken);
    }
}
```

Applications that want automatic background cleanup can opt in explicitly:

```csharp
services.AddAshlarPostgres(connectionString);
services.AddAshlarPostgresCleanupHostedService(options =>
{
    options.CleanupInterval = TimeSpan.FromHours(1);
    options.RemoveExpiredSessionsAfter = TimeSpan.FromDays(7);
});
```

Cleanup uses bounded batches and the application's `TimeProvider`, so repeated or concurrent runs are safe and deterministic in tests. `MaxBatchesPerRun` lets one cleanup run catch up on backlog without making the run unbounded.

Cleanup diagnostics are available through `IAshlarCleanupDiagnostics` when provider cleanup is registered:

```csharp
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

var diagnostics = serviceProvider.GetRequiredService<IAshlarCleanupDiagnostics>();
var result = await diagnostics.CheckAsync(cancellationToken);
```

The result reports provider name, `CheckedAt`, whether cleanup is configured, whether `AshlarCleanupOptions` are valid, cleanup interval, batch size, max batches per run, and enabled/disabled cleanup category counts. It returns `Healthy` when configured options are valid, `Unhealthy` when configured options are invalid, and `NotSupported` when cleanup diagnostics cannot read configured cleanup options. The result does not query cleanup tables or expose provider internals.

## Configuration Validation
Ashlar includes provider-neutral configuration validation for startup and deployment checks. It reports incomplete or development-oriented setup without sending email, writing data, starting background work, or querying provider infrastructure.

```csharp
using Ashlar.Operational.Configuration;

var validator = serviceProvider.GetRequiredService<IAshlarConfigurationValidator>();
var result = await validator.ValidateAsync();

foreach (var issue in result.Issues)
{
    Console.WriteLine($"{issue.Severity}: {issue.Code} - {issue.Message}");
}
```

`AddAshlarIdentity()` registers the validator automatically; applications can also call `AddAshlarConfigurationValidation()` directly. This is not a replacement for health checks: health checks answer whether running infrastructure is healthy, while configuration validation answers whether Ashlar appears safely and completely configured. Warnings may be acceptable in development. Production apps should pay attention to missing repositories, missing secret protection, missing or null email delivery for email-based flows, `NullSecurityEventSink`, in-memory authentication rate limiting, and no durable transaction provider.

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

Audit event payloads include stable event types, timestamps, target user/session ids when known, tenant id, actor user id, provider identity, IP address, user agent, correlation id, outcome, failure reason, and string properties. Audit events must not contain raw session tokens, passwords, one-time codes, credential values, protected payloads, password hashes, recovery codes, or other secrets.

The **Ashlar.Postgres** package includes a PostgreSQL-backed sink:

```csharp
services.AddAshlarPostgres(connectionString);
services.AddAshlarPostgresAuditSink();
```

### Security Event Browsing
Ashlar also exposes provider-neutral read APIs for admin and operations tooling:

```csharp
var result = await securityEventAdministration.SearchSecurityEventsAsync(new SearchSecurityEventsRequest
{
    Tenant = null, // unscoped/admin-wide; use TenantContext.Global for only global events
    UserId = userId,
    EventTypes = new HashSet<string> { AshlarSecurityEventTypes.SessionCreated },
    OccurredFrom = DateTimeOffset.UtcNow.AddDays(-7),
    Limit = 50
});
```

Use `ISecurityEventAdministrationService` from application code and implement or register `ISecurityEventAdministrationRepository` for the backing store. `Ashlar.Postgres` and `Ashlar.Sqlite` provide repository implementations that query `ashlar_security_events` without exposing provider-specific row ids or JSON storage details.

These APIs do not authorize callers by themselves. Host applications must protect any endpoint or job that uses them with admin authorization and an appropriate step-up policy. Event properties are intended only for operational diagnostics and must never contain secrets.

## Security Notifications
Ashlar includes generic opt-in security notifications to notify users about important account and security events, such as new sign-ins, session revocations, and MFA changes.

Register the notification services:

```csharp
services.AddAshlarSecurityNotifications(options =>
{
    options.Enabled = true;
    options.EnabledTypes.Add(SecurityNotificationType.SignIn);
    options.EnabledTypes.Add(SecurityNotificationType.TotpEnrolled);
    options.EnabledTypes.Add(SecurityNotificationType.TotpDisabled);
    // ... other types
});
```

Security notifications use the existing `IEmailSender` abstraction, so ensure you have registered a functional email sender. Notifications are sent post-commit for transactional flows and include only safe context (no secrets or raw tokens).

Repeated notifications are suppressed by recipient and notification type to avoid user spam. Most notification types default to a 15 minute cooldown; `SuspiciousAuthenticationAttempt` defaults to a 1 hour cooldown because it can be triggered by hostile verification traffic after authentication rate limits are reached. Applications can override or disable a cooldown:

```csharp
services.AddAshlarSecurityNotifications(options =>
{
    options.Enabled = true;
    options.EnabledTypes.Add(SecurityNotificationType.SignIn);
    options.Cooldowns[SecurityNotificationType.SignIn] = TimeSpan.FromHours(1);
    options.Cooldowns[SecurityNotificationType.TotpDisabled] = TimeSpan.Zero; // always send
});
```

### Supported Event Types
- `SignIn`: New session created.
- `SessionRevoked`: A specific session was revoked.
- `AllOtherSessionsRevoked`: All other sessions for the user were revoked.
- `AllSessionsRevoked`: All sessions for the user were revoked.
- `TotpEnrolled`: MFA enrollment completed.
- `TotpDisabled`: MFA disabled.
- `RecoveryCodesGenerated`: New recovery codes generated.
- `InvitationAccepted`: User invitation accepted.
- `BootstrapCompleted`: System bootstrap completed.
- `EmailChanged`: User email address changed.
- `EmailVerificationCompleted`: Email verification successful.
- `SuspiciousAuthenticationAttempt`: Rate-limited authentication handshake attempt.

### Customizing Templates
Applications can override the default notification subjects and bodies:

```csharp
services.AddAshlarSecurityNotifications(options =>
{
    options.Enabled = true;
    options.EnabledTypes.Add(SecurityNotificationType.SignIn);
    options.TemplateOverrides[SecurityNotificationType.SignIn] = new SecurityNotificationTemplate
    {
        Subject = "Security Alert: New Sign-in",
        Body = "We detected a new sign-in to your account at {OccurredAt} from {IpAddress}."
    };
});
```

Available placeholders in templates:
- `{RecipientEmail}`: The email address receiving the notification.
- `{OccurredAt}`: The timestamp of the event.
- `{Type}`: The notification type.
- `{IpAddress}`: The approximate IP address (if enabled and available).
- `{UserAgent}`: The user agent string (if enabled and available).
- `{SessionId}`: The session identifier (if applicable).

## Contributions
Contributions are welcome! Read the [contributing guide](CONTRIBUTING.md) to get started.

## License
This project is licensed under the [MIT License](LICENSE).
