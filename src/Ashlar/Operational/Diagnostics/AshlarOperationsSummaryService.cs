using Microsoft.Extensions.Logging;

namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Composes existing Ashlar diagnostics into one safe operational summary.
/// </summary>
/// <param name="schemaDiagnostics">Available storage schema diagnostics.</param>
/// <param name="cleanupDiagnostics">Available diagnostics sources for cleanup configuration and cleanup scheduling.</param>
/// <param name="rateLimiterDiagnostics">Available authentication rate limiter diagnostics.</param>
/// <param name="emailOutboxDiagnostics">Available diagnostics sources for aggregate email outbox delivery state.</param>
/// <param name="webhookOutboxDiagnostics">Available security-event webhook outbox diagnostics.</param>
/// <param name="timeProvider">Clock used to stamp fallback component results.</param>
/// <param name="logger">Optional logger for contained diagnostic failures.</param>
public sealed class AshlarOperationsSummaryService(
    IEnumerable<IAshlarSchemaDiagnostics> schemaDiagnostics,
    IEnumerable<IAshlarCleanupDiagnostics> cleanupDiagnostics,
    IEnumerable<IAuthenticationRateLimiterDiagnostics> rateLimiterDiagnostics,
    IEnumerable<IEmailOutboxDiagnostics> emailOutboxDiagnostics,
    IEnumerable<ISecurityEventWebhookOutboxDiagnostics> webhookOutboxDiagnostics,
    TimeProvider timeProvider,
    ILogger<AshlarOperationsSummaryService>? logger = null) : IAshlarOperationsSummaryService
{
    private const string SchemaComponent = "schema";
    private const string CleanupComponent = "cleanup";
    private const string RateLimiterComponent = "authenticationRateLimiter";
    private const string EmailOutboxComponent = "emailOutbox";
    private const string WebhookOutboxComponent = "securityEventWebhookOutbox";
    private static readonly Action<ILogger, string, Exception?> LogDiagnosticFailure =
        LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(1, nameof(LogDiagnosticFailure)),
            "Ashlar operations summary diagnostic failed for {Component}.");

    private readonly IAshlarSchemaDiagnostics? _schemaDiagnostics = (schemaDiagnostics ?? throw new ArgumentNullException(nameof(schemaDiagnostics))).FirstOrDefault();
    private readonly IAshlarCleanupDiagnostics? _cleanupDiagnostics = (cleanupDiagnostics ?? throw new ArgumentNullException(nameof(cleanupDiagnostics))).FirstOrDefault();
    private readonly IAuthenticationRateLimiterDiagnostics? _rateLimiterDiagnostics = (rateLimiterDiagnostics ?? throw new ArgumentNullException(nameof(rateLimiterDiagnostics))).FirstOrDefault();
    private readonly IEmailOutboxDiagnostics? _emailOutboxDiagnostics = (emailOutboxDiagnostics ?? throw new ArgumentNullException(nameof(emailOutboxDiagnostics))).FirstOrDefault();
    private readonly ISecurityEventWebhookOutboxDiagnostics? _webhookOutboxDiagnostics = (webhookOutboxDiagnostics ?? throw new ArgumentNullException(nameof(webhookOutboxDiagnostics))).FirstOrDefault();
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public async Task<AshlarOperationsSummary> GetSummaryAsync(CancellationToken cancellationToken = default)
    {
        EnsureNotCanceled(cancellationToken);
        var schema = await CheckComponentAsync(
            SchemaComponent,
            async token => _schemaDiagnostics == null ? CreateNotSupportedSchema() : Project(await _schemaDiagnostics.CheckAsync(token)),
            token => CreateUnknownSchema(token),
            cancellationToken);
        EnsureNotCanceled(cancellationToken);
        var cleanup = await CheckComponentAsync(
            CleanupComponent,
            async token => _cleanupDiagnostics == null ? CreateNotSupportedCleanup() : Project(await _cleanupDiagnostics.CheckAsync(token)),
            token => CreateUnknownCleanup(token),
            cancellationToken);
        EnsureNotCanceled(cancellationToken);
        var rateLimiter = await CheckComponentAsync(
            RateLimiterComponent,
            async token => _rateLimiterDiagnostics == null ? CreateNotSupportedRateLimiter() : Project(await _rateLimiterDiagnostics.CheckAsync(token)),
            token => CreateUnknownRateLimiter(token),
            cancellationToken);
        EnsureNotCanceled(cancellationToken);
        var emailOutbox = await CheckComponentAsync(
            EmailOutboxComponent,
            async token => _emailOutboxDiagnostics == null ? CreateNotSupportedOutbox() : Project(await _emailOutboxDiagnostics.CheckAsync(token)),
            token => CreateUnknownOutbox(token),
            cancellationToken);
        EnsureNotCanceled(cancellationToken);
        var webhookOutbox = await CheckComponentAsync(
            WebhookOutboxComponent,
            async token => _webhookOutboxDiagnostics == null ? CreateNotSupportedOutbox() : Project(await _webhookOutboxDiagnostics.CheckAsync(token)),
            token => CreateUnknownOutbox(token),
            cancellationToken);
        EnsureNotCanceled(cancellationToken);

        var components = new AshlarOperationsComponentSummary[]
        {
            schema,
            cleanup,
            rateLimiter,
            emailOutbox,
            webhookOutbox
        };
        var issues = CreateIssues(
            (SchemaComponent, schema),
            (CleanupComponent, cleanup),
            (RateLimiterComponent, rateLimiter),
            (EmailOutboxComponent, emailOutbox),
            (WebhookOutboxComponent, webhookOutbox));

        return new AshlarOperationsSummary(
            DeriveOverallStatus(components),
            _timeProvider.GetUtcNow(),
            schema,
            cleanup,
            rateLimiter,
            emailOutbox,
            webhookOutbox,
            issues);
    }

    private async Task<TSummary> CheckComponentAsync<TSummary>(
        string component,
        Func<CancellationToken, Task<TSummary>> check,
        Func<CancellationToken, TSummary> fallback,
        CancellationToken cancellationToken)
        where TSummary : AshlarOperationsComponentSummary
    {
        try
        {
            return await check(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            if (logger != null)
            {
                LogDiagnosticFailure(logger, component, ex);
            }

            return fallback(cancellationToken);
        }
    }

    private static AshlarSchemaOperationsSummary Project(AshlarSchemaDiagnosticResult result)
    {
        return new AshlarSchemaOperationsSummary(
            result.Status,
            result.CheckedAt,
            result.SchemaStatus,
            result.AppliedMigrationCount,
            result.ExpectedMigrationCount,
            result.MissingMigrationCount);
    }

    private static AshlarCleanupOperationsSummary Project(AshlarCleanupDiagnosticResult result)
    {
        return new AshlarCleanupOperationsSummary(
            result.Status,
            result.CheckedAt,
            result.Configured,
            result.OptionsValid,
            result.CleanupInterval,
            result.BatchSize,
            result.MaxBatchesPerRun,
            result.EnabledCategoryCount,
            result.DisabledCategoryCount);
    }

    private static AshlarAuthenticationRateLimiterOperationsSummary Project(AuthenticationRateLimiterDiagnosticResult result)
    {
        return new AshlarAuthenticationRateLimiterOperationsSummary(
            result.Status,
            result.CheckedAt,
            result.Configured,
            result.Distributed,
            result.Persistent,
            result.ExpiredRowCount,
            result.ActiveKeyCount,
            result.BlockedKeyCount,
            result.CleanupConfigured,
            result.CleanupInterval,
            result.MaxCleanupRows);
    }

    private static AshlarOutboxOperationsSummary Project(EmailOutboxDiagnosticResult result)
    {
        return new AshlarOutboxOperationsSummary(
            result.Status,
            result.CheckedAt,
            result.PendingCount,
            result.ScheduledCount,
            result.LockedCount,
            result.ExpiredLockCount,
            result.FailedCount,
            result.OldestPendingAt,
            result.OldestFailedAt,
            result.MaxAttempts,
            result.PollingInterval,
            result.BatchSize);
    }

    private static AshlarOutboxOperationsSummary Project(SecurityEventWebhookOutboxDiagnosticResult result)
    {
        return new AshlarOutboxOperationsSummary(
            result.Status,
            result.CheckedAt,
            result.PendingCount,
            result.ScheduledCount,
            result.LockedCount,
            result.ExpiredLockCount,
            result.FailedCount,
            result.OldestPendingAt,
            result.OldestFailedAt,
            result.MaxAttempts,
            result.PollingInterval,
            result.BatchSize);
    }

    private AshlarSchemaOperationsSummary CreateUnknownSchema(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new AshlarSchemaOperationsSummary(
            AshlarDiagnosticStatus.Unknown,
            _timeProvider.GetUtcNow(),
            AshlarSchemaStatus.Unknown,
            null,
            null,
            null);
    }

    private AshlarCleanupOperationsSummary CreateUnknownCleanup(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new AshlarCleanupOperationsSummary(
            AshlarDiagnosticStatus.Unknown,
            _timeProvider.GetUtcNow(),
            false,
            false,
            null,
            null,
            null,
            null,
            null);
    }

    private AshlarAuthenticationRateLimiterOperationsSummary CreateUnknownRateLimiter(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new AshlarAuthenticationRateLimiterOperationsSummary(
            AshlarDiagnosticStatus.Unknown,
            _timeProvider.GetUtcNow(),
            false,
            false,
            false,
            null,
            null,
            null,
            null,
            null,
            null);
    }

    private AshlarOutboxOperationsSummary CreateUnknownOutbox(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new AshlarOutboxOperationsSummary(
            AshlarDiagnosticStatus.Unknown,
            _timeProvider.GetUtcNow(),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null);
    }

    private AshlarSchemaOperationsSummary CreateNotSupportedSchema()
    {
        return new AshlarSchemaOperationsSummary(
            AshlarDiagnosticStatus.NotSupported,
            _timeProvider.GetUtcNow(),
            AshlarSchemaStatus.Unknown,
            null,
            null,
            null);
    }

    private AshlarCleanupOperationsSummary CreateNotSupportedCleanup()
    {
        return new AshlarCleanupOperationsSummary(
            AshlarDiagnosticStatus.NotSupported,
            _timeProvider.GetUtcNow(),
            false,
            false,
            null,
            null,
            null,
            null,
            null);
    }

    private AshlarAuthenticationRateLimiterOperationsSummary CreateNotSupportedRateLimiter()
    {
        return new AshlarAuthenticationRateLimiterOperationsSummary(
            AshlarDiagnosticStatus.NotSupported,
            _timeProvider.GetUtcNow(),
            false,
            false,
            false,
            null,
            null,
            null,
            null,
            null,
            null);
    }

    private AshlarOutboxOperationsSummary CreateNotSupportedOutbox()
    {
        return new AshlarOutboxOperationsSummary(
            AshlarDiagnosticStatus.NotSupported,
            _timeProvider.GetUtcNow(),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null);
    }

    private static AshlarDiagnosticStatus DeriveOverallStatus(IEnumerable<AshlarOperationsComponentSummary> components)
    {
        var statuses = components.Select(component => component.Status).ToArray();
        if (statuses.Any(status => status == AshlarDiagnosticStatus.Unhealthy))
        {
            return AshlarDiagnosticStatus.Unhealthy;
        }

        if (statuses.Any(status => status is AshlarDiagnosticStatus.Degraded or AshlarDiagnosticStatus.Unknown)
            || statuses.Any(status => !Enum.IsDefined(status)))
        {
            return AshlarDiagnosticStatus.Degraded;
        }

        return AshlarDiagnosticStatus.Healthy;
    }

    private static System.Collections.ObjectModel.ReadOnlyCollection<AshlarOperationsIssue> CreateIssues(
        params (string Component, AshlarOperationsComponentSummary Summary)[] components)
    {
        return Array.AsReadOnly(components
            .Where(component => component.Summary.Status is not AshlarDiagnosticStatus.Healthy and not AshlarDiagnosticStatus.NotSupported)
            .Select(component => new AshlarOperationsIssue(
                component.Component,
                component.Summary.Status))
            .ToArray());
    }

    private static void EnsureNotCanceled(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
    }
}
