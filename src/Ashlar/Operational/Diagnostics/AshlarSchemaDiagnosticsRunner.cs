using System.Reflection;

namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared schema diagnostics result mapping for Ashlar persistence providers.
/// </summary>
/// <param name="providerName">Persistence provider name reported in diagnostic results.</param>
/// <param name="expectedMigrationNames">Ordered migration resource names expected by the current Ashlar package.</param>
/// <param name="minimumProviderVersion">Minimum provider schema or engine version expected by Ashlar.</param>
public sealed class AshlarSchemaDiagnosticsRunner(
    string providerName,
    IReadOnlyCollection<string> expectedMigrationNames,
    string? minimumProviderVersion)
{
    private const string NotInitializedReason = "Schema has not been initialized.";
    private const string PendingMigrationsReason = "Schema has pending migrations.";
    private const string UnknownReason = "Schema diagnostics could not query provider state.";

    /// <summary>
    /// Checks provider schema state and returns a sanitized diagnostics result.
    /// </summary>
    /// <typeparam name="TConnection">Provider connection type used by diagnostics queries.</typeparam>
    /// <param name="timeProvider">Clock used to stamp the diagnostic result.</param>
    /// <param name="openConnectionAsync">Callback that opens a provider connection for diagnostics.</param>
    /// <param name="getProviderVersionAsync">Callback that reads the provider schema or engine version.</param>
    /// <param name="getSchemaJournalCountAsync">Callback that counts schema journal entries.</param>
    /// <param name="getAppliedMigrationNamesAsync">Callback that reads applied migration names.</param>
    /// <param name="logException">Callback that records diagnostics failures without exposing provider query details.</param>
    /// <param name="cancellationToken">Token for aborting provider diagnostics work.</param>
    /// <returns>Sanitized provider schema health status and migration details.</returns>
    public async Task<AshlarSchemaDiagnosticResult> CheckAsync<TConnection>(
        TimeProvider timeProvider,
        Func<CancellationToken, ValueTask<TConnection>> openConnectionAsync,
        Func<TConnection, CancellationToken, Task<string?>> getProviderVersionAsync,
        Func<TConnection, CancellationToken, Task<int>> getSchemaJournalCountAsync,
        Func<TConnection, CancellationToken, Task<IReadOnlyCollection<string>>> getAppliedMigrationNamesAsync,
        Action<Exception> logException,
        CancellationToken cancellationToken = default)
        where TConnection : IAsyncDisposable
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(openConnectionAsync);
        ArgumentNullException.ThrowIfNull(getProviderVersionAsync);
        ArgumentNullException.ThrowIfNull(getSchemaJournalCountAsync);
        ArgumentNullException.ThrowIfNull(getAppliedMigrationNamesAsync);
        ArgumentNullException.ThrowIfNull(logException);

        var checkedAt = timeProvider.GetUtcNow();
        AshlarSchemaDiagnosticResult result;

        try
        {
            await using var connection = await openConnectionAsync(cancellationToken);
            var providerVersion = await getProviderVersionAsync(connection, cancellationToken);

            if (await getSchemaJournalCountAsync(connection, cancellationToken) == 0)
            {
                result = CreateNotInitializedResult(checkedAt, providerVersion);
            }
            else
            {
                var appliedMigrationNames = await getAppliedMigrationNamesAsync(connection, cancellationToken);
                result = CreateAppliedResult(checkedAt, providerVersion, appliedMigrationNames);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logException(ex);
            return CreateUnknownResult(checkedAt);
        }

        return result;
    }

    /// <summary>
    /// Gets embedded schema migration names from an assembly.
    /// </summary>
    /// <param name="assembly">Assembly containing embedded Ashlar schema migration resources.</param>
    /// <returns>The ordered embedded schema migration resource names.</returns>
    public static string[] GetExpectedMigrationNames(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);

        return assembly.GetManifestResourceNames()
            .Where(name => name.Contains(".Schema.Scripts.", StringComparison.Ordinal) && name.EndsWith(".sql", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private AshlarSchemaDiagnosticResult CreateNotInitializedResult(DateTimeOffset checkedAt, string? providerVersion)
    {
        return new AshlarSchemaDiagnosticResult(
            AshlarDiagnosticStatus.Unhealthy,
            providerName,
            NotInitializedReason,
            checkedAt,
            AshlarSchemaStatus.NotInitialized,
            0,
            expectedMigrationNames.Count,
            expectedMigrationNames.Count,
            null,
            LatestExpectedMigrationName,
            minimumProviderVersion,
            providerVersion);
    }

    private AshlarSchemaDiagnosticResult CreateAppliedResult(
        DateTimeOffset checkedAt,
        string? providerVersion,
        IReadOnlyCollection<string> appliedMigrationNames)
    {
        var appliedMigrationNameSet = appliedMigrationNames.ToHashSet(StringComparer.Ordinal);
        var missingMigrationCount = expectedMigrationNames.Count(name => !appliedMigrationNameSet.Contains(name));
        var schemaStatus = missingMigrationCount == 0 ? AshlarSchemaStatus.Current : AshlarSchemaStatus.PendingMigrations;
        var status = schemaStatus == AshlarSchemaStatus.Current ? AshlarDiagnosticStatus.Healthy : AshlarDiagnosticStatus.Unhealthy;

        return new AshlarSchemaDiagnosticResult(
            status,
            providerName,
            schemaStatus == AshlarSchemaStatus.Current ? null : PendingMigrationsReason,
            checkedAt,
            schemaStatus,
            appliedMigrationNames.Count,
            expectedMigrationNames.Count,
            missingMigrationCount,
            appliedMigrationNames.LastOrDefault(),
            LatestExpectedMigrationName,
            minimumProviderVersion,
            providerVersion);
    }

    private AshlarSchemaDiagnosticResult CreateUnknownResult(DateTimeOffset checkedAt)
    {
        return new AshlarSchemaDiagnosticResult(
            AshlarDiagnosticStatus.Unknown,
            providerName,
            UnknownReason,
            checkedAt,
            AshlarSchemaStatus.Unknown,
            null,
            expectedMigrationNames.Count,
            null,
            null,
            LatestExpectedMigrationName,
            minimumProviderVersion,
            null);
    }

    private string? LatestExpectedMigrationName => expectedMigrationNames.LastOrDefault();
}
