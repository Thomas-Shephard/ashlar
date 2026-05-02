# Ashlar.Postgres

PostgreSQL persistence implementation for Ashlar identity and authentication sessions.

## Requirements

- **PostgreSQL 15+**: This package utilizes the `NULLS NOT DISTINCT` clause in unique indexes to provide robust multi-tenant email uniqueness.

## Setup

Add the package to your project and register the services in `Program.cs`:

```csharp
using Microsoft.Extensions.DependencyInjection;

// Using a connection string
services.AddAshlarPostgres(connectionString);

// OR using an existing NpgsqlDataSource
services.AddAshlarPostgres(myDataSource);
```

## Schema Management

Ashlar.Postgres uses [DbUp](https://dbup.github.io/) for schema migrations. You can initialize the schema during application startup:

```csharp
await serviceProvider.InitializeAshlarPostgresSchemaAsync();
```

This will create the following tables:
- `ashlar_users`: Stores user identity and audit metadata.
- `ashlar_credentials`: Stores credentials with optimistic concurrency support.
- `ashlar_sessions`: Stores durable authentication sessions using hashed session tokens only.
- `ashlar_schema_versions`: Internal DbUp table to track applied migrations for this package.

## Features

- **Multi-tenancy**: First-class support for `ITenantUser`.
- **Atomic Operations**: Optimistic concurrency (version checking) for all credential updates and consumption.
- **Session Persistence**: Stores session expiry, last-seen, revocation, request metadata, and deterministic token hashes. Raw session tokens are never stored.
- **Case-Insensitive Identity**: Emails are normalized and looked up case-insensitively using optimized indexes.
- **Modern Npgsql**: Built for `NpgsqlDataSource` and .NET 8+.

Session token hashing assumes the application session-issuing code creates high-entropy random tokens.
Ashlar uses a dedicated fast session token hasher rather than password hashing because session tokens are server-generated secrets that are checked frequently.
