# Ashlar.Sqlite

SQLite persistence infrastructure for Ashlar.

This package is an early durable SQLite provider for Ashlar. It currently provides dependency injection registration, schema initialization, scoped connection/transaction infrastructure, bootstrap state persistence, identity users and credentials, invitations, authentication sessions, MFA handshakes, passkey challenges, authorization grants, audit persistence, durable authentication rate limiting, and best-effort cleanup. It does not yet provide email outbox dispatch.

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
- `IInvitationRepository`
- `IAuthenticationSessionRepository`
- `IAuthenticationHandshakeRepository`
- `IPasskeyChallengeRepository`
- `IAuthorizationGrantRepository`
- `ISecurityEventSink`
- `IUserSecurityEventSummaryRepository`
- `IAuthenticationRateLimiter`
- `IAshlarCleanupService`

Not implemented yet:

- email outbox sender and dispatcher

## SQLite Limitations

SQLite stores GUIDs, timestamps, provider values, version tokens, and JSON payloads as `TEXT` in this schema. Authorization grant metadata and security event properties are serialized text, not `JSONB`, and provider code should not rely on database JSON operators.

SQLite does not provide PostgreSQL equivalents for `FOR UPDATE SKIP LOCKED`, advisory locks, `ctid`, or PostgreSQL row-level locking behavior. Authentication handshake `forUpdate` requests are treated as provider-neutral update intent and rely on SQLite's active transaction/write-safe path plus atomic updates rather than row-level `FOR UPDATE`.

SQLite rate limiting persists fixed-window state in `ashlar_rate_limits` and uses Ashlar's scoped transaction infrastructure so standalone checks run through SQLite's `BEGIN IMMEDIATE` write path. This is intended for single-process deployments, not distributed rate limiting across application instances.

SQLite cleanup deletes bounded batches with SQLite-compatible `rowid` subqueries. It is single-instance best effort and does not provide PostgreSQL-style multi-worker coordination with `SKIP LOCKED`.

Tenant email uniqueness is represented with SQLite-compatible partial unique indexes: one index for tenant-scoped users and one index for users without a tenant.

## Planned Slices

The intended repository implementation order is:

1. Email outbox sender and single-instance dispatcher.
2. Reusable provider contract tests shared with PostgreSQL where practical.

## Related Packages

- `Ashlar`: Core identity, authorization, messaging, and security primitives.
- `Ashlar.Postgres`: PostgreSQL persistence and email outbox support.
- `Ashlar.AspNetCore`: ASP.NET Core session authentication and authorization integration.
