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

services.AddDataProtection();
services.AddAshlarDataProtectionSecretProtector();
services.AddAshlarPostgres(connectionString);
```

Add authentication providers for the flows your application supports:

```csharp
services.AddAshlarMagicLinkSignIn();
services.AddAshlarEmailCodeSignIn();
services.AddAshlarTotp();
services.AddAshlarRecoveryCodes();
```

Ashlar keeps the core package framework-neutral. ASP.NET Core cookies, PostgreSQL persistence, SMTP delivery, and hosted background workers live in companion packages.

## Related Packages

- `Ashlar.AspNetCore`: ASP.NET Core session authentication and authorization integration.
- `Ashlar.Postgres`: PostgreSQL repositories, schema management, audit persistence, rate limiting, cleanup, and email outbox support.
- `Ashlar.Email.Smtp`: SMTP email transport and sender built on MailKit.
