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
```

Ashlar keeps the core package framework-neutral. ASP.NET Core cookies, PostgreSQL persistence, SMTP delivery, and hosted background workers live in companion packages.

## Account Security Posture

`IAccountSecurityService.GetUserSecurityPostureAsync` returns a non-secret posture model for account and admin screens. It separates primary sign-in methods from additional verification factors, reports the current MFA policy requirement, tells whether the user is ready for required verification, and lists missing factor families with display-safe names.

Use `PrimaryCredentials` for sign-in methods, `AdditionalVerificationFactors` for authenticator apps, recovery codes, and policy-eligible passkeys, and `Policy` for readiness and missing factors. Do not render raw provider keys as the main UI label. The posture model does not expose credential values, token hashes, public keys, passkey ceremony JSON, recovery codes, password hashes, or protected secrets.

## Admin User Reads

`IUserAdministrationService` provides reusable read-only operations for admin and operations UIs: `SearchUsersAsync` returns safe `UserSummary` rows, and `GetUserDetailAsync` combines a summary with `UserSecurityPosture`. Provider packages implement the required `IUserAdministrationRepository`, so hosts do not need to query Ashlar provider tables directly.

These APIs do not authorize callers by themselves. Host applications must protect any endpoints that expose them with their own admin authorization, audit policy, and step-up requirements.

## Admin Session Reads

`IAuthenticationSessionAdministrationService` provides read-only session and device browsing for admin and operations UIs. Use `SearchAuthenticationSessionsAsync` to filter by tenant, user, provider, active/revoked state, and timestamp ranges, or `GetAuthenticationSessionAsync` for a single safe detail row.

Provider packages implement `IAuthenticationSessionAdministrationRepository`, so hosts do not need to query session tables directly. These APIs do not authorize callers by themselves; protect endpoints with admin authorization and step-up policy. Raw session tokens, token hashes, and session metadata are not exposed.

## Related Packages

- `Ashlar.AspNetCore`: ASP.NET Core session authentication and authorization integration.
- `Ashlar.Postgres`: PostgreSQL repositories, schema management, account-lockout persistence, audit persistence, rate limiting, cleanup, and email outbox support.
- `Ashlar.Email.Smtp`: SMTP email transport and sender built on MailKit.
