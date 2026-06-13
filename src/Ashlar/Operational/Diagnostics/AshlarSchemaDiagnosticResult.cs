namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Describes the provider-neutral outcome of an Ashlar storage schema check.
/// </summary>
/// <param name="Status">Overall diagnostic status for the schema check.</param>
/// <param name="ProviderName">Persistence provider that produced the diagnostic result.</param>
/// <param name="Reason">Optional provider-safe reason when the check is unavailable, degraded, or failed.</param>
/// <param name="CheckedAt">UTC time when the diagnostic check completed.</param>
/// <param name="SchemaStatus">Provider-neutral schema state inferred from migration metadata.</param>
/// <param name="AppliedMigrationCount">Number of migrations already applied by the provider.</param>
/// <param name="ExpectedMigrationCount">Number of migrations expected by the current Ashlar package.</param>
/// <param name="MissingMigrationCount">Number of expected migrations not yet applied.</param>
/// <param name="LatestAppliedMigrationName">Latest applied migration name, when the provider can report it.</param>
/// <param name="LatestExpectedMigrationName">Latest migration name expected by the current Ashlar package.</param>
/// <param name="MinimumProviderVersion">Minimum provider schema or engine version expected by Ashlar.</param>
/// <param name="ProviderVersion">Provider schema or engine version observed during the check.</param>
public sealed record AshlarSchemaDiagnosticResult(
    AshlarDiagnosticStatus Status,
    string ProviderName,
    string? Reason,
    DateTimeOffset CheckedAt,
    AshlarSchemaStatus SchemaStatus,
    int? AppliedMigrationCount,
    int? ExpectedMigrationCount,
    int? MissingMigrationCount,
    string? LatestAppliedMigrationName,
    string? LatestExpectedMigrationName,
    string? MinimumProviderVersion,
    string? ProviderVersion);
