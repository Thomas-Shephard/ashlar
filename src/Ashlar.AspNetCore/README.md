# Ashlar.AspNetCore

ASP.NET Core integration for Ashlar session authentication and authorization policies.

## Installation

```bash
dotnet add package Ashlar.AspNetCore
```

## Minimal Usage

Register Ashlar core services, persistence, and ASP.NET Core session cookies:

```csharp
services.AddAshlarIdentity();
services.AddAshlarPostgres(connectionString);

services.AddAshlarAspNetCoreSessions(options =>
{
    options.CookieName = "__Host-ashlar";
});
```

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

app.MapDelete("/api/sessions/{id:guid}", RevokeSessionAsync)
    .RequireFreshMfaIfAvailable();

app.MapDelete("/api/passkeys/{id:guid}", DeletePasskeyAsync)
    .RequireAuthorization("Account.Security");
```

Step-up policies use the current Ashlar session metadata emitted by the session authentication handler and evaluate it with `IStepUpAuthenticationService`. Missing, malformed, stale, or disallowed verification metadata denies authorization. Unauthenticated users still follow normal ASP.NET Core challenge behavior.

Use `.RequireFreshMfa()` for high-risk operations such as changing recovery settings, registering or revoking passkeys, resetting MFA, changing email addresses, or administrator account actions. Use `.RequireFreshMfaIfAvailable()` for lower-risk sensitive operations where avoiding lockout is more important than hard enforcement. Conditional mode loads `IAccountSecurityService.GetUserSecurityPostureAsync`, matches usable `AdditionalVerificationFactors` against the policy's allowed factors, and only then applies the same freshness check as strict mode. If posture cannot be loaded safely, authorization is denied. By default the conditional policy treats `totp`, `recovery_code`, and `passkey` as eligible; add custom factor strings through `AshlarStepUpOptions.AllowedFactors`.

Conditional mode is weaker than strict mode because users with no usable eligible factor are allowed through. It is intended for adaptive protection, not for operations that must be blocked until MFA is enrolled.

Apps should handle a step-up authorization failure by redirecting the user to, or returning API metadata for, an application-owned step-up flow. The complete step-up UX and broader sample endpoint protection are intentionally separate from this package integration.

## Related Packages

- `Ashlar`: Core identity, authorization, messaging, and security primitives.
- `Ashlar.Postgres`: PostgreSQL persistence for sessions, users, credentials, invitations, and authorization grants.
- `Ashlar.Email.Smtp`: SMTP email delivery for Ashlar email flows.
