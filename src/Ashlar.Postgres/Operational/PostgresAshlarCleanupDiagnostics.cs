using Ashlar.Operational;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Operational;

internal sealed class PostgresAshlarCleanupDiagnostics(
    IOptions<AshlarCleanupOptions> options,
    TimeProvider timeProvider) : AshlarCleanupDiagnostics("Postgres", options, timeProvider);
