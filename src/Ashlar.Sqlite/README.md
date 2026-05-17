# Ashlar.Sqlite

SQLite persistence infrastructure for Ashlar.

This package is an early durable SQLite provider for Ashlar. It currently provides dependency injection registration, schema initialization, scoped connection/transaction infrastructure, bootstrap state persistence, identity users, and credentials. It does not yet provide sessions, invitations, MFA handshakes, passkey challenges, authorization grants, auditing, cleanup, rate limiting, or email outbox dispatch.

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

Not implemented yet:

- invitation repositories
- authentication session and MFA handshake repositories
- passkey challenge repository
- authorization grant repository
- audit sink
- cleanup service
- rate limiter
- email outbox sender and dispatcher

## SQLite Limitations

SQLite stores GUIDs, timestamps, provider values, version tokens, and JSON payloads as `TEXT` in this schema. JSON payloads are serialized text, not `JSONB`, and provider code should not rely on database JSON operators.

SQLite does not provide PostgreSQL equivalents for `FOR UPDATE SKIP LOCKED`, advisory locks, `ctid`, or PostgreSQL row-level locking behavior. Future cleanup and outbox implementations will use SQLite-compatible single-instance strategies and will not provide PostgreSQL-equivalent multi-instance coordination.

Tenant email uniqueness is represented with SQLite-compatible partial unique indexes: one index for tenant-scoped users and one index for users without a tenant.

## Planned Slices

The intended repository implementation order is:

1. Invitations, sessions, MFA handshakes, and passkey challenges.
2. Authorization grants and audit sink.
3. Rate limiting and cleanup.
4. Email outbox sender and single-instance dispatcher.
5. Reusable provider contract tests shared with PostgreSQL where practical.

## Related Packages

- `Ashlar`: Core identity, authorization, messaging, and security primitives.
- `Ashlar.Postgres`: PostgreSQL persistence and email outbox support.
- `Ashlar.AspNetCore`: ASP.NET Core session authentication and authorization integration.
