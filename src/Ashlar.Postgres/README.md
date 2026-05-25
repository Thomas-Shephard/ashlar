# Ashlar.Postgres

PostgreSQL persistence for Ashlar identity, credentials, MFA handshakes, sessions/devices, invitations, authorization grants, security audit events, rate limiting, cleanup, and the email outbox.

## Installation

```bash
dotnet add package Ashlar.Postgres
```

## Requirements

- **PostgreSQL 15+**: This package utilizes the `NULLS NOT DISTINCT` clause in unique indexes to provide robust multi-tenant email uniqueness.
- **Single schema per Ashlar installation**: The built-in schema scripts create the `ashlar_*` tables in the current PostgreSQL schema.

## Setup

Register the services in `Program.cs`:

```csharp
using Microsoft.Extensions.DependencyInjection;

// Using a connection string
services.AddAshlarPostgres(connectionString);

// OR using an existing NpgsqlDataSource
services.AddAshlarPostgres(myDataSource);

// Register PostgreSQL-backed security audit persistence (Optional)
services.AddAshlarPostgresAuditSink();
```

For a typical application, combine this package with the core Ashlar services:

```csharp
services.AddAshlarIdentity();
services.AddAshlarAuthorization();
services.AddAshlarPostgres(connectionString);
```

## Schema Management

Ashlar.Postgres uses [DbUp](https://dbup.github.io/) for schema migrations. You can initialize the schema during application startup:

```csharp
await serviceProvider.InitializeAshlarPostgresSchemaAsync();
```

This will create the following tables:
- `ashlar_users`: Stores user identity and audit metadata.
- `ashlar_credentials`: Stores credentials with optimistic concurrency support. Provider identity is globally unique by provider type, provider name, and provider key, and credential status/revocation state is enforced by the database.
- `ashlar_sessions`: Stores durable authentication sessions using hashed session tokens only, plus safe authentication metadata for primary sign-in and recent additional verification.
- `ashlar_passkey_challenges`: Stores short-lived WebAuthn registration, authentication, and MFA factor challenges.
- `ashlar_security_events`: Stores structured security audit events.
- `ashlar_rate_limits`: Stores distributed rate limit state.
- `ashlar_bootstrap_state`: Stores the system initialization status.
- `ashlar_schema_versions`: Internal DbUp table to track applied migrations for this package.

The schema enforces tenant-scoped user email uniqueness, unique token hashes for sessions, invitations, and MFA handshakes, singleton bootstrap state, and mutually exclusive terminal states for invitations and email outbox rows.

## Schema Diagnostics

`AddAshlarPostgres(...)` registers `IAshlarSchemaDiagnostics` for operational monitoring. Resolve it from DI and call `CheckAsync()` to inspect whether the embedded Ashlar schema scripts have been applied:

```csharp
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

var diagnostics = serviceProvider.GetRequiredService<IAshlarSchemaDiagnostics>();
var result = await diagnostics.CheckAsync();
```

The result reports provider name, PostgreSQL server version, required provider version, expected/applied/missing migration counts, latest expected/applied migration names, and `CheckedAt`.

Schema diagnostics return:

- `Healthy` with `SchemaStatus.Current` when all embedded scripts are applied.
- `Unhealthy` with `SchemaStatus.NotInitialized` when the schema journal table is missing.
- `Unhealthy` with `SchemaStatus.PendingMigrations` when the journal exists but not all embedded scripts are recorded.
- `Unknown` with `SchemaStatus.Unknown` when provider state cannot be queried. The reason string is intentionally generic and safe for logs or health responses.

## Cleanup Diagnostics

`AddAshlarPostgresCleanup(...)` and `AddAshlarPostgresCleanupHostedService(...)` register `IAshlarCleanupDiagnostics`. Resolve it from DI and call `CheckAsync()` to inspect safe cleanup configuration facts:

```csharp
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

var diagnostics = serviceProvider.GetRequiredService<IAshlarCleanupDiagnostics>();
var result = await diagnostics.CheckAsync();
```

The result reports provider name, `CheckedAt`, whether cleanup is configured, whether `AshlarCleanupOptions` are valid, cleanup interval, batch size, max batches per run, and enabled/disabled cleanup category counts.

Cleanup diagnostics return:

- `Healthy` when cleanup is configured and cleanup options are valid.
- `Unhealthy` when cleanup is configured but cleanup options are invalid.
- `NotSupported` when cleanup services/options are not configured.

Cleanup diagnostics do not query provider tables, track last run state, or expose SQL predicates, table names, or sensitive data.

## Features

- **Bootstrap Persistence**: Durable storage for system initialization status using `PostgresBootstrapStateRepository`.
- **Audit Persistence**: Durable storage for security-sensitive events using `PostgresSecurityEventSink`.
- **Multi-tenancy**: First-class support for `ITenantUser`.
- **Tenant Email Isolation**: The same normalized email can exist in different tenants, but not twice in the same tenant or twice without a tenant.
- **Atomic Operations**: Optimistic concurrency (version checking) for all credential updates and consumption.
- **Session Persistence**: Stores session expiry, last-seen, revocation, request metadata, safe authentication metadata, and deterministic token hashes. Raw session tokens are never stored.
- **Admin Session Reads**: Implements `IAuthenticationSessionAdministrationRepository` for provider-neutral read-only session/device browsing. Raw session tokens and token hashes are never returned.
- **Case-Insensitive Identity**: Emails are normalized and looked up case-insensitively using optimized indexes.
- **Modern Npgsql**: Built for `NpgsqlDataSource` and .NET 8+.

## Email Outbox

The PostgreSQL-backed email outbox allows you to persist email messages durably within your database transactions and dispatch them asynchronously.
The dispatcher claims rows with `FOR UPDATE SKIP LOCKED`, so multiple application instances can poll the same outbox table without intentionally sending the same pending row twice.
The outbox persists `EmailMessage.Sensitivity` as a provider-neutral string (`Normal` or `ContainsLiveSecret`) and restores it before dispatch. Token-bearing Ashlar flows use this sender as an `ITransactionalEmailOutboxSender`, so the queued message commits or rolls back with the token credential.

### Registration

Register the outbox sender and the hosted dispatcher in `Program.cs`:

```csharp
// Register the outbox sender (implements ITransactionalEmailOutboxSender)
services.AddAshlarPostgresEmailOutboxSender();

// Register the hosted dispatcher with a custom transport
services.AddAshlarPostgresEmailOutboxHostedService<MySmtpTransport>(options =>
{
    options.BatchSize = 100;
    options.PollingInterval = TimeSpan.FromSeconds(5);
    options.MaxAttempts = 10;
});
```

Use `AddAshlarPostgresEmailOutboxDispatcher<TTransport>()` when you want to register the provider-neutral `IEmailOutboxDispatcher` without the hosted polling loop.

### Implementing a Transport

The dispatcher requires an implementation of `IEmailTransport` to physically deliver the messages:

```csharp
public class MySmtpTransport : IEmailTransport
{
    public async Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        // Use your preferred SMTP client or API to send the email
        // ...
    }
}
```

### Transactional Integrity

When using the PostgreSQL outbox sender, calling `IEmailSender.SendAsync` inside an Ashlar PostgreSQL transaction will automatically include the message in that transaction:

```csharp
await using (var tx = await transactionProvider.BeginTransactionAsync())
{
    // ... perform identity operations ...

    // This message is only persisted if the transaction commits
    await emailSender.SendAsync(new EmailMessage("user@example.com", "Welcome", "Hello!"));

    await tx.CommitAsync();
}
```

### Cleanup and Retention

The email outbox and short-lived passkey challenges integrate with the Ashlar cleanup service. You can configure retention periods via `AshlarCleanupOptions`:

```csharp
services.Configure<AshlarCleanupOptions>(options =>
{
    options.RemoveSentEmailsAfter = TimeSpan.FromDays(7);
    options.RemoveFailedEmailsAfter = TimeSpan.FromDays(30);
    options.RemoveExpiredPasskeyChallengesAfter = TimeSpan.FromDays(1);
    options.RemoveConsumedPasskeyChallengesAfter = TimeSpan.FromDays(1);
});
```

Session token hashing assumes the application session-issuing code creates high-entropy random tokens.
Ashlar uses a dedicated fast session token hasher rather than password hashing because session tokens are server-generated secrets that are checked frequently.

## Related Packages

- `Ashlar`: Core identity, authorization, messaging, and security primitives.
- `Ashlar.AspNetCore`: ASP.NET Core session authentication and authorization integration.
- `Ashlar.Email.Smtp`: SMTP transport for direct email delivery or the PostgreSQL email outbox dispatcher.
