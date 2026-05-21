using System.Reflection;

namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Provides shared schema diagnostics result mapping for Ashlar persistence providers.
/// </summary>
/// <param name="providerName">The provider name value.</param>
/// <param name="expectedMigrationNames">The expected migration names value.</param>
/// <param name="minimumProviderVersion">The minimum provider version value.</param>
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
    /// <typeparam name="TConnection">The provider connection type.</typeparam>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="openConnectionAsync">The open connection callback.</param>
    /// <param name="getProviderVersionAsync">The provider version callback.</param>
    /// <param name="getSchemaJournalCountAsync">The schema journal count callback.</param>
    /// <param name="getAppliedMigrationNamesAsync">The applied migration names callback.</param>
    /// <param name="logException">The exception logging callback.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The schema diagnostics result.</returns>
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
    /// <param name="assembly">The assembly value.</param>
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
