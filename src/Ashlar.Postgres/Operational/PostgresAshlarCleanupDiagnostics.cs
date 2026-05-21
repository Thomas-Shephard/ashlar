using Ashlar.Operational;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Operational;

internal sealed class PostgresAshlarCleanupDiagnostics(
    IOptions<AshlarCleanupOptions> options,
    TimeProvider timeProvider) : IAshlarCleanupDiagnostics
{
    private const string ProviderName = "Postgres";
    private static readonly AshlarCleanupDiagnosticsRunner DiagnosticsRunner = new(ProviderName);

    private readonly IOptions<AshlarCleanupOptions> _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    public Task<AshlarCleanupDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(DiagnosticsRunner.Check(_timeProvider, _options.Value, configured: true));
    }
}
