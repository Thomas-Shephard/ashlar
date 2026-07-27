# Ashlar.Sqlite

SQLite persistence infrastructure for Ashlar.

This package is an early durable SQLite provider for Ashlar. It currently provides dependency injection registration, schema initialization, transaction-aware persistence, bootstrap state persistence, identity users and credentials, account lockout, invitations, authentication sessions, read-only admin session browsing, MFA handshakes, passkey challenges, authorization grants, audit persistence, durable authentication rate limiting, SQLite-backed email outbox enqueue/dispatch, and best-effort cleanup.

## Supported Scenario

`Ashlar.Sqlite` is intended for single-process and single-application-instance self-hosted deployments. It is not intended to match PostgreSQL's multi-instance coordination guarantees.

Use `Ashlar.Postgres` when you need distributed rate limiting, multi-instance outbox polling, multi-worker cleanup coordination, or PostgreSQL-specific operational guarantees.

## Installation

```bash
dotnet add package Ashlar.Sqlite
```

## Setup

Register the SQLite infrastructure in `Program.cs`:

```csharp
using Microsoft.Extensions.DependencyInjection;

services.AddAshlarSqlite("Data Source=ashlar.db");
services.AddAshlarSqliteAuditSink();
```

`AddAshlarSqliteAuditSink()` wires provider-backed `IPersistentSecurityEventSink` storage into Ashlar's security event fan-out. A successful `RecordAsync` call means the security event has been written to SQLite; write failures are returned to the caller.

Initialize the schema during application startup:

```csharp
await serviceProvider.InitializeAshlarSqliteSchemaAsync();
```

The initializer applies embedded SQLite scripts idempotently and records applied scripts in `ashlar_schema_versions`.

## Schema Diagnostics

`AddAshlarSqlite(...)` registers `IAshlarSchemaDiagnostics` for operational monitoring. Resolve it from DI and call `CheckAsync()` to inspect whether the embedded Ashlar schema scripts have been applied:

```csharp
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

var diagnostics = serviceProvider.GetRequiredService<IAshlarSchemaDiagnostics>();
var result = await diagnostics.CheckAsync();
```

The result reports provider name, SQLite library version, expected/applied/missing migration counts, latest expected/applied migration names, and `CheckedAt`.

Schema diagnostics return:

- `Healthy` with `SchemaStatus.Current` when all embedded scripts are applied.
- `Unhealthy` with `SchemaStatus.NotInitialized` when the schema journal table is missing.
- `Unhealthy` with `SchemaStatus.PendingMigrations` when the journal exists but not all embedded scripts are recorded.
- `Unknown` with `SchemaStatus.Unknown` when provider state cannot be queried. The reason string is intentionally generic and safe for logs or health responses.

## Cleanup Diagnostics

`AddAshlarSqliteCleanupHostedService(...)` registers `IAshlarCleanupDiagnostics`. Resolve it from DI and call `CheckAsync()` to inspect safe cleanup configuration facts:

```csharp
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

var diagnostics = serviceProvider.GetRequiredService<IAshlarCleanupDiagnostics>();
var result = await diagnostics.CheckAsync();
```

The result reports provider name, `CheckedAt`, whether cleanup is configured, whether `AshlarCleanupOptions` are valid, cleanup interval, batch size, max batches per run, and enabled/disabled cleanup category counts.

SQLite cleanup joins the active scoped Ashlar transaction when one exists, and otherwise runs on a fresh SQLite connection.

Cleanup diagnostics return:

- `Healthy` when cleanup is configured and cleanup options are valid.
- `Unhealthy` when cleanup is configured but cleanup options are invalid.
- `NotSupported` when cleanup services/options are not configured.

Cleanup diagnostics do not query provider tables, track last run state, or expose SQL predicates, table names, or sensitive data.

Register SQLite email outbox enqueue support when application code should persist email messages instead of delivering them inline:

```csharp
services.AddAshlarSqliteEmailOutboxSender();
```

Register the hosted dispatcher loop for a transport implementation:

```csharp
services.AddAshlarSqliteEmailOutboxHostedService<SmtpEmailTransport>(options =>
{
    options.BatchSize = 25;
    options.PollingInterval = TimeSpan.FromSeconds(5);
});
```

The sender participates in Ashlar SQLite transactions, so queued emails commit or roll back with the surrounding Ashlar transaction.
It implements `ITransactionalEmailOutboxSender`, which lets token-bearing Ashlar flows enqueue durable emails before committing the token credential. The outbox persists `EmailMessage.Sensitivity` as `Normal` or `ContainsLiveSecret` and restores it before dispatch.

## Current Status

Implemented:

- `AddAshlarSqlite(...)`
- `InitializeAshlarSqliteSchemaAsync(...)`
- Ashlar transaction integration through `IAshlarTransactionProvider`
- `BEGIN IMMEDIATE` root transactions
- initial SQLite-compatible `ashlar_*` schema
- `IBootstrapStateRepository`
- `IUserRepository` and `ICredentialRepository` for users and credentials
- `IInvitationRepository`
- `IAuthenticationSessionRepository`
- `IAuthenticationSessionAdministrationRepository`
- `IAuthenticationHandshakeRepository`
- `IPasskeyChallengeRepository`
- `IAuthorizationGrantRepository`
- `ISecurityEventSink`
- `IUserSecurityEventSummaryRepository`
- `IAuthenticationRateLimiter`
- `IEmailSender` via `AddAshlarSqliteEmailOutboxSender(...)`
- `SqliteEmailOutboxHostedService` via `AddAshlarSqliteEmailOutboxHostedService<TTransport>(...)`
- `IAshlarSchemaDiagnostics`
- `IAshlarCleanupDiagnostics`

## SQLite Limitations

SQLite stores GUIDs, timestamps, provider values, version tokens, and JSON payloads as `TEXT` in this schema. Authorization grant metadata and security event properties are serialized text, not `JSONB`, and provider code should not rely on database JSON operators.

SQLite does not provide PostgreSQL equivalents for `FOR UPDATE SKIP LOCKED`, advisory locks, `ctid`, or PostgreSQL row-level locking behavior. Authentication handshake `forUpdate` requests are treated as provider-neutral update intent and rely on SQLite's active transaction/write-safe path plus atomic updates rather than row-level `FOR UPDATE`.

SQLite rate limiting persists fixed-window state in `ashlar_rate_limits`. Standalone checks run through SQLite's `BEGIN IMMEDIATE` write path. This is intended for single-process deployments, not distributed rate limiting across application instances.

SQLite email outbox dispatch is single-instance best effort. It claims pending rows with SQLite-compatible compare-and-set updates on `locked_until` and `locked_by`, then loads rows claimed by the current dispatch batch. It does not emulate PostgreSQL `FOR UPDATE SKIP LOCKED` and should not be used as a distributed multi-worker outbox coordinator.

SQLite cleanup deletes bounded batches with SQLite-compatible `rowid` subqueries. It is single-instance best effort and does not provide PostgreSQL-style multi-worker coordination with `SKIP LOCKED`.

Tenant email uniqueness is represented with SQLite-compatible partial unique indexes: one index for tenant-scoped users and one index for users without a tenant.

## Related Packages

- `Ashlar`: Core identity, authorization, messaging, and security primitives.
- `Ashlar.Postgres`: PostgreSQL persistence and email outbox support.
- `Ashlar.AspNetCore`: ASP.NET Core session authentication and authorization integration.
