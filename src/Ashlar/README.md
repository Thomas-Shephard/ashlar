# Ashlar

Core identity, authentication, authorization, messaging, and security primitives for .NET 8+ applications.

## Installation

```bash
dotnet add package Ashlar
```

## Minimal Usage

Register the core services, then provide persistence and secret protection through your application or a companion package:

```csharp
services.AddAshlarIdentity();
services.AddAshlarAuthorization();

// Required before using credential features that store protected secrets.
// Register an ISecretProtector implementation from a companion package or your application.
services.AddAshlarPostgres(connectionString);
```

Core Ashlar owns the `ISecretProtector` abstraction but does not ship a default implementation. Hosts must register an implementation before using credential features that store or read protected secrets, such as TOTP shared secrets, recovery credentials, and email-change secrets. ASP.NET Core Data Protection integration is provided by `Ashlar.AspNetCore`.

Add authentication providers for the flows your application supports:

```csharp
services.AddAshlarMagicLinkSignIn();
services.AddAshlarEmailCodeSignIn();
services.AddAshlarTotp();
services.AddAshlarRecoveryCodes();
services.AddAshlarNoMfaPolicy();
```

Authentication providers that participate in MFA orchestration require an explicit MFA policy. Use `AddAshlarNoMfaPolicy()` only for deliberate no-MFA composition; use `AddAshlarRequireMfaWhenCredentialExists(...)`, `AddAshlarRequireMfaForAllUsers(...)`, or a custom `IMfaPolicyEvaluator` when authentication must be gated by MFA.

Ashlar includes ASP.NET Core OAuth and OpenID Connect integration. Cookie session integration, PostgreSQL persistence, SMTP delivery, and hosted background workers live in companion packages.

## OAuth and OpenID Connect

Configure validated external sign-in providers directly from the Ashlar package:

```csharp
using Ashlar.OAuth.Providers.Google;

services.AddAshlarOAuth(options => options.AddGoogle(google =>
{
    google.ClientId = configuration["Authentication:Google:ClientId"]!;
    google.ClientSecret = configuration["Authentication:Google:ClientSecret"]!;
}));
```

All OIDC providers key external credentials by the validated issuer and subject claims. Ashlar preserves the validated security token issuer in its temporary external ticket, so provider claim mapping cannot remove it; tokens with missing or blank issuers fail closed.

Account linking consumes Ashlar-validated temporary external tickets and requires an Ashlar-issued fresh MFA proof bound to the target user, tenant, session, and linking purpose. Applications cannot submit raw authentication providers or assertions to credential mutation.

## Account Security Posture

`IAccountSecurityService.GetSecurityPostureAsync` returns the validated current session's non-secret posture model for self-service account screens. Administrator screens use the actor-bound administration reader. The posture separates primary sign-in methods from additional verification factors, reports the current MFA policy requirement, tells whether the user is ready for required verification, and lists missing factor families with display-safe names.

Use `PrimaryCredentials` for sign-in methods, `AdditionalVerificationFactors` for authenticator apps, recovery codes, and policy-eligible passkeys, and `Policy` for readiness and missing factors. Do not render raw provider keys as the main UI label. The posture model does not expose credential values, token hashes, public keys, passkey ceremony JSON, recovery codes, password hashes, or protected secrets.

## Admin User Reads

`IUserAdministrationReader` provides reusable read-only operations for admin and operations UIs. Every call requires `AccountSecurityActorContext` separately from its query request, an explicit tenant/global/all-tenant scope, an active-session-bound fresh MFA proof for `administration-read`, matching audit identity, and host authorizer approval. Reads are durably audited and fail closed when audit persistence fails. Provider repositories remain provider-facing and results are safe projections.

## Admin Session Reads

`IAuthenticationSessionAdministrationReader` uses the same actor-bound `administration-read` proof, scope, host authorization, and durable audit boundary as other administration reads.

Provider packages implement `IAuthenticationSessionAdministrationRepository`; raw session tokens, token hashes, and session metadata are not exposed.

## Related Packages

- `Ashlar.AspNetCore`: ASP.NET Core session authentication and authorization integration.
- `Ashlar.Postgres`: PostgreSQL repositories, schema management, account-lockout persistence, audit persistence, rate limiting, cleanup, and email outbox support.
- `Ashlar.Email.Smtp`: SMTP email transport and sender built on MailKit.
