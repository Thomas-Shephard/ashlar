namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Represents a provider-neutral result for Ashlar storage schema diagnostics.
/// </summary>
/// <param name="Status">The diagnostic status value.</param>
/// <param name="ProviderName">The provider name value.</param>
/// <param name="Reason">The reason value.</param>
/// <param name="CheckedAt">The checked at value.</param>
/// <param name="SchemaStatus">The provider-neutral schema state value.</param>
/// <param name="AppliedMigrationCount">The applied migration count value.</param>
/// <param name="ExpectedMigrationCount">The expected migration count value.</param>
/// <param name="MissingMigrationCount">The missing migration count value.</param>
/// <param name="LatestAppliedMigrationName">The latest applied migration name value.</param>
/// <param name="LatestExpectedMigrationName">The latest expected migration name value.</param>
/// <param name="MinimumProviderVersion">The minimum provider version value.</param>
/// <param name="ProviderVersion">The provider version value.</param>
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
