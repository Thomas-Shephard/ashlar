using Ashlar.Operational;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Operational;

internal sealed class SqliteAshlarCleanupDiagnostics(
    IOptions<AshlarCleanupOptions> options,
    TimeProvider timeProvider) : AshlarCleanupDiagnostics("Sqlite", options, timeProvider);
