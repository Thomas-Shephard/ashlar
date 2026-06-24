# Ashlar.AspNetCore

ASP.NET Core integration for Ashlar session authentication and authorization policies.

## Installation

```bash
dotnet add package Ashlar.AspNetCore
```

## Minimal Usage

Register Ashlar core services, persistence, secret protection, and ASP.NET Core session cookies:

```csharp
services.AddAshlarIdentity();
services.AddAshlarPostgres(connectionString);

services.AddDataProtection();
services.AddAshlarDataProtectionSecretProtector();

services.AddAshlarAspNetCoreSessions(options =>
{
    options.CookieName = "__Host-ashlar";
});
```

`AddAshlarDataProtectionSecretProtector()` registers the ASP.NET Core Data Protection implementation for Ashlar's core `ISecretProtector` abstraction. Register it before using Ashlar credential features that store or read protected secrets, such as TOTP shared secrets, recovery credentials, and email-change secrets. The host app must still configure Data Protection, including key persistence and protection policy appropriate for the environment.

Use the middleware in the normal ASP.NET Core order:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

Sign users in by creating an Ashlar authentication session and issuing the configured cookie:

```csharp
var signInManager = httpContext.RequestServices.GetRequiredService<IAshlarSignInManager>();
await signInManager.SignInAsync(httpContext, userId);
```

Authorization policies can be backed by Ashlar authorization grants:

```csharp
services.AddAshlarAuthorization();
services.AddAshlarAspNetCoreAuthorization(options =>
{
    options.AddRolePolicy("admin", "admin");
    options.AddPermissionPolicy("project.manage", "project.manage", scope =>
    {
        scope.ScopeType = "project";
        scope.ScopeIdRouteValueName = "projectId";
    });
});
```

Fresh step-up verification can also be required through normal ASP.NET Core authorization. Strict fresh MFA always requires a recent additional verification. Conditional fresh MFA checks the user's account security posture first and requires a recent verification only when the account has a usable eligible additional verification factor:

```csharp
services.AddAshlarAspNetCoreAuthorization(options =>
{
    options.StepUp.FreshnessWindow = TimeSpan.FromMinutes(10);
    options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Totp);
    options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.RecoveryCode);
    options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);

    options.RequireFreshMfa();
    options.RequireFreshMfaIfAvailable();
    options.AddAshlarStepUpPolicy("Account.Security", stepUp =>
    {
        stepUp.FreshnessWindow = TimeSpan.FromMinutes(5);
        stepUp.AllowedFactors.Add(AuthenticationFactorTypes.Totp);
    });
});
```

Use the named policy or endpoint helper on sensitive endpoints:

```csharp
app.MapPost("/account/change-email", ChangeEmailAsync)
    .RequireFreshMfa();

app.MapDelete("/api/sessions/{id:guid}", RevokeSessionForCurrentUserAsync)
    .RequireFreshMfaIfAvailable();

app.MapDelete("/api/passkeys/{id:guid}", DeletePasskeyAsync)
    .RequireAuthorization("Account.Security");
```

Step-up policies require the Ashlar session authentication handler to validate the request and populate `HttpContext.Items[AshlarHttpContextItems.AuthenticationSession]` with the current `AuthenticationSession`. Ashlar-shaped claims are only used as a consistency check against that validated session; claims by themselves cannot satisfy `.RequireFreshMfa()` or `.RequireFreshMfaIfAvailable()`. Missing session items, malformed or mismatched Ashlar claims, stale verification, or disallowed verification metadata deny authorization. Unauthenticated users still follow normal ASP.NET Core challenge behavior.

Use `.RequireFreshMfa()` for high-risk operations such as changing recovery settings, registering or revoking passkeys, resetting MFA, changing email addresses, or administrator account actions. Use `.RequireFreshMfaIfAvailable()` for lower-risk sensitive operations where avoiding lockout is more important than hard enforcement. Conditional mode loads `IAccountSecurityService.GetUserSecurityPostureAsync`, matches usable `AdditionalVerificationFactors` against the policy's allowed factors, and only then applies the same freshness check as strict mode. If posture cannot be loaded safely, authorization is denied. By default the conditional policy treats `totp`, `recovery_code`, and `passkey` as eligible; add custom factor strings through `AshlarStepUpOptions.AllowedFactors`.

Conditional mode is weaker than strict mode because users with no usable eligible factor are allowed through. It is intended for adaptive protection, not for operations that must be blocked until MFA is enrolled.

Apps should handle a step-up authorization failure by redirecting the user to, or returning API metadata for, an application-owned step-up flow. The complete step-up UX and broader sample endpoint protection are intentionally separate from this package integration.

## Health Checks

Ashlar.AspNetCore can expose Ashlar operational diagnostics through ASP.NET Core health checks:

```csharp
services.AddAshlarIdentity();
services.AddAshlarPostgres(connectionString);

services.AddHealthChecks()
    .AddAshlarHealthChecks();
```

The convenience registration adds five checks with stable names:

- `ashlar_schema`
- `ashlar_email_outbox`
- `ashlar_security_event_webhook_outbox`
- `ashlar_cleanup`
- `ashlar_rate_limiter`

Missing optional diagnostics services are reported with the check's not-supported status, which defaults to `Degraded`. Register individual checks when you want custom tags, names, or options:

```csharp
services.AddHealthChecks()
    .AddAshlarSchema(tags: ["ashlar", "storage"])
    .AddAshlarEmailOutbox(options =>
    {
        options.PendingCountThreshold = 1_000;
        options.FailedCountThreshold = 10;
        options.ExpiredLockCountThreshold = 5;
        options.OldestPendingAgeThreshold = TimeSpan.FromMinutes(15);
    }, tags: ["ashlar", "messaging"])
    .AddAshlarSecurityEventWebhookOutbox(options =>
    {
        options.PendingCountThreshold = 1_000;
        options.FailedCountThreshold = 10;
        options.ExpiredLockCountThreshold = 5;
        options.OldestPendingAgeThreshold = TimeSpan.FromMinutes(15);
    }, tags: ["ashlar", "webhooks"])
    .AddAshlarCleanup(options =>
    {
        options.NotSupportedStatus = HealthStatus.Healthy;
    })
    .AddAshlarRateLimiter();
```

Health check data contains only safe aggregate diagnostic values such as provider name, diagnostic status, counts, timestamps, and configured batch or interval values. Provider packages do not depend on ASP.NET Core health checks; the adapters depend only on Ashlar diagnostic interfaces.

## Related Packages

- `Ashlar`: Core identity, authorization, messaging, and security primitives.
- `Ashlar.Postgres`: PostgreSQL persistence for sessions, users, credentials, invitations, and authorization grants.
- `Ashlar.Email.Smtp`: SMTP email delivery for Ashlar email flows.
