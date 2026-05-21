# Ashlar.Sqlite

SQLite persistence infrastructure for Ashlar.

This package is an early durable SQLite provider for Ashlar. It currently provides dependency injection registration, schema initialization, scoped connection/transaction infrastructure, bootstrap state persistence, identity users and credentials, invitations, authentication sessions, MFA handshakes, passkey challenges, authorization grants, audit persistence, durable authentication rate limiting, SQLite-backed email outbox enqueue/dispatch, and best-effort cleanup.

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
```

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

Register SQLite email outbox enqueue support when application code should persist email messages instead of delivering them inline:

```csharp
services.AddAshlarSqliteEmailOutboxSender();
```

Register a dispatcher for a transport implementation:

```csharp
services.AddAshlarSqliteEmailOutboxDispatcher<SmtpEmailTransport>(options =>
{
    options.BatchSize = 25;
    options.PollingInterval = TimeSpan.FromSeconds(5);
});
```

Register the hosted dispatcher loop:

```csharp
services.AddAshlarSqliteEmailOutboxHostedService<SmtpEmailTransport>();
```

The sender participates in Ashlar SQLite transactions through `ISqliteConnectionProvider`, so queued emails commit or roll back with the surrounding Ashlar transaction.

## Current Status

Implemented:

- `AddAshlarSqlite(...)`
- `InitializeAshlarSqliteSchemaAsync(...)`
- scoped SQLite connection reuse through `ISqliteConnectionProvider`
- Ashlar transaction integration through `IAshlarTransactionProvider`
- `BEGIN IMMEDIATE` root transactions
- nested transaction participants that join the active provider transaction
- initial SQLite-compatible `ashlar_*` schema
- `IBootstrapStateRepository`
- `IIdentityRepository` for users and credentials
- `IInvitationRepository`
- `IAuthenticationSessionRepository`
- `IAuthenticationHandshakeRepository`
- `IPasskeyChallengeRepository`
- `IAuthorizationGrantRepository`
- `ISecurityEventSink`
- `IUserSecurityEventSummaryRepository`
- `IAuthenticationRateLimiter`
- `IEmailSender` via `AddAshlarSqliteEmailOutboxSender(...)`
- `IEmailOutboxDispatcher` via `AddAshlarSqliteEmailOutboxDispatcher<TTransport>(...)`
- `SqliteEmailOutboxHostedService<TTransport>` via `AddAshlarSqliteEmailOutboxHostedService<TTransport>(...)`
- `IAshlarCleanupService`
- `IAshlarSchemaDiagnostics`

Not implemented yet:

- provider contract tests shared with PostgreSQL

## SQLite Limitations

SQLite stores GUIDs, timestamps, provider values, version tokens, and JSON payloads as `TEXT` in this schema. Authorization grant metadata and security event properties are serialized text, not `JSONB`, and provider code should not rely on database JSON operators.

SQLite does not provide PostgreSQL equivalents for `FOR UPDATE SKIP LOCKED`, advisory locks, `ctid`, or PostgreSQL row-level locking behavior. Authentication handshake `forUpdate` requests are treated as provider-neutral update intent and rely on SQLite's active transaction/write-safe path plus atomic updates rather than row-level `FOR UPDATE`.

SQLite rate limiting persists fixed-window state in `ashlar_rate_limits` and uses Ashlar's scoped transaction infrastructure so standalone checks run through SQLite's `BEGIN IMMEDIATE` write path. This is intended for single-process deployments, not distributed rate limiting across application instances.

SQLite email outbox dispatch is single-instance best effort. It claims pending rows with SQLite-compatible compare-and-set updates on `locked_until` and `locked_by`, then loads rows claimed by the dispatcher instance. It does not emulate PostgreSQL `FOR UPDATE SKIP LOCKED` and should not be used as a distributed multi-worker outbox coordinator.

SQLite cleanup deletes bounded batches with SQLite-compatible `rowid` subqueries. It is single-instance best effort and does not provide PostgreSQL-style multi-worker coordination with `SKIP LOCKED`.

Tenant email uniqueness is represented with SQLite-compatible partial unique indexes: one index for tenant-scoped users and one index for users without a tenant.

## Planned Slices

The intended repository implementation order is:

1. Reusable provider contract tests shared with PostgreSQL where practical.

## Related Packages

- `Ashlar`: Core identity, authorization, messaging, and security primitives.
- `Ashlar.Postgres`: PostgreSQL persistence and email outbox support.
- `Ashlar.AspNetCore`: ASP.NET Core session authentication and authorization integration.
