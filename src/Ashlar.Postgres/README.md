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

// Register PostgreSQL-backed security audit persistence (Optional)
services.AddAshlarPostgresAuditSink();
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
- `ashlar_security_events`: Stores structured security audit events.
- `ashlar_rate_limits`: Stores distributed rate limit state.
- `ashlar_schema_versions`: Internal DbUp table to track applied migrations for this package.

## Features

- **Audit Persistence**: Durable storage for security-sensitive events using `PostgresSecurityEventSink`.
- **Multi-tenancy**: First-class support for `ITenantUser`.
- **Atomic Operations**: Optimistic concurrency (version checking) for all credential updates and consumption.
- **Session Persistence**: Stores session expiry, last-seen, revocation, request metadata, and deterministic token hashes. Raw session tokens are never stored.
- **Case-Insensitive Identity**: Emails are normalized and looked up case-insensitively using optimized indexes.
- **Modern Npgsql**: Built for `NpgsqlDataSource` and .NET 8+.

## Email Outbox

The PostgreSQL-backed email outbox allows you to persist email messages durably within your database transactions and dispatch them asynchronously.

### Registration

Register the outbox sender and the hosted dispatcher in `Program.cs`:

```csharp
// Register the outbox sender (implements IEmailSender)
services.AddAshlarPostgresEmailOutbox();

// Register the hosted dispatcher with a custom transport
services.AddAshlarPostgresEmailOutboxHostedService<MySmtpTransport>(options =>
{
    options.BatchSize = 100;
    options.PollingInterval = TimeSpan.FromSeconds(5);
    options.MaxAttempts = 10;
});
```

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

When using `AddAshlarPostgresEmailOutbox`, calling `IEmailSender.SendAsync` inside an Ashlar PostgreSQL transaction will automatically include the message in that transaction:

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

The email outbox integrates with the Ashlar cleanup service. You can configure retention periods via `AshlarCleanupOptions`:

```csharp
services.Configure<AshlarCleanupOptions>(options =>
{
    options.RemoveSentEmailsAfter = TimeSpan.FromDays(7);
    options.RemoveFailedEmailsAfter = TimeSpan.FromDays(30);
});
```

Session token hashing assumes the application session-issuing code creates high-entropy random tokens.
Ashlar uses a dedicated fast session token hasher rather than password hashing because session tokens are server-generated secrets that are checked frequently.
