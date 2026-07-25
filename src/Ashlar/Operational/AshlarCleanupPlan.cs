using Ashlar.Messaging;

namespace Ashlar.Operational;

/// <summary>
/// Describes a provider-specific cleanup delete command target.
/// </summary>
/// <param name="Category">Stable cleanup <paramref name="Category" /> name reported in cleanup results.</param>
/// <param name="TableName">Provider table targeted by the <paramref name="Category" /> cleanup plan.</param>
/// <param name="Predicate">Provider-specific delete predicate for rows older than the retention cutoff.</param>
/// <param name="OrderColumn">Provider column used to make bounded deletes deterministic.</param>
public sealed record AshlarCleanupDeleteDefinition(string Category, string TableName, string Predicate, string OrderColumn);

/// <summary>
/// Describes a provider-neutral Ashlar cleanup <paramref name="Category" />.
/// </summary>
/// <param name="Category">Stable cleanup <paramref name="Category" /> name reported in cleanup results.</param>
/// <param name="TableName">Provider table targeted by the <paramref name="Category" /> cleanup plan.</param>
/// <param name="PredicateTemplate">The provider-neutral predicate template.</param>
/// <param name="OrderColumn">Provider column used to make bounded deletes deterministic.</param>
/// <param name="Retention">Option selector that returns the retention window for this <paramref name="Category" />.</param>
/// <param name="GetCount">Reads this <paramref name="Category" /> deleted-row count from a cleanup result.</param>
/// <param name="AddCount">Adds this <paramref name="Category" /> deleted-row count to a cleanup result.</param>
public sealed record AshlarCleanupCategoryDefinition(
    string Category,
    string TableName,
    string PredicateTemplate,
    string OrderColumn,
    Func<AshlarCleanupOptions, TimeSpan?> Retention,
    Func<AshlarCleanupResult, int> GetCount,
    Func<AshlarCleanupResult, int, AshlarCleanupResult> AddCount);

/// <summary>
/// Shared cleanup category plan for Ashlar persistence providers.
/// </summary>
public static class AshlarCleanupPlan
{
    private const string SessionsTable = "ashlar_sessions";
    private const string CredentialsTable = "ashlar_credentials";
    private const string AuthorizationGrantsTable = "ashlar_authorization_grants";
    private const string InvitationsTable = "ashlar_invitations";
    private const string HandshakesTable = "ashlar_mfa_handshakes";
    private const string RememberedMfaDevicesTable = "ashlar_remembered_mfa_devices";
    private const string RateLimitsTable = "ashlar_rate_limits";
    private const string PasskeyChallengesTable = "ashlar_passkey_challenges";
    private const string SecurityEventsTable = "ashlar_security_events";
    private const string EmailOutboxTable = "ashlar_email_outbox";
    private const string SecurityEventWebhookOutboxTable = "ashlar_security_event_webhook_outbox";
    private const string ExpiresAtColumn = "expires_at";
    private const string RevokedAtColumn = "revoked_at";
    private const string AcceptedAtColumn = "accepted_at";
    private const string CompletedAtColumn = "completed_at";
    private const string OccurredAtColumn = "occurred_at";
    private const string ConsumedAtColumn = "consumed_at";
    private const string SentAtColumn = "sent_at";
    private const string FailedAtColumn = "failed_at";
    private const string DiscardedAtColumn = "discarded_at";
    private const string NormalEmailSensitivity = nameof(EmailMessageSensitivity.Normal);
    private const string CutoffToken = "{cutoff}";
    private const string TrueToken = "{true}";
    private const string FalseToken = "{false}";

    private static readonly AshlarCleanupCategoryDefinition[] CategoryDefinitions =
    [
        new("expired_sessions", SessionsTable, $"expires_at < {CutoffToken} AND revoked_at IS NULL", ExpiresAtColumn, options => options.RemoveExpiredSessionsAfter, result => result.ExpiredSessions, (result, count) => result with { ExpiredSessions = result.ExpiredSessions + count }),
        new("revoked_sessions", SessionsTable, $"revoked_at IS NOT NULL AND revoked_at < {CutoffToken}", RevokedAtColumn, options => options.RemoveRevokedSessionsAfter, result => result.RevokedSessions, (result, count) => result with { RevokedSessions = result.RevokedSessions + count }),
        new("expired_credentials", CredentialsTable, $"expires_at IS NOT NULL AND expires_at < {CutoffToken} AND revoked_at IS NULL", ExpiresAtColumn, options => options.RemoveExpiredCredentialsAfter, result => result.ExpiredCredentials, (result, count) => result with { ExpiredCredentials = result.ExpiredCredentials + count }),
        new("revoked_credentials", CredentialsTable, $"revoked_at IS NOT NULL AND revoked_at < {CutoffToken}", RevokedAtColumn, options => options.RemoveRevokedCredentialsAfter, result => result.RevokedCredentials, (result, count) => result with { RevokedCredentials = result.RevokedCredentials + count }),
        new("expired_invitations", InvitationsTable, $"expires_at < {CutoffToken} AND accepted_at IS NULL AND revoked_at IS NULL", ExpiresAtColumn, options => options.RemoveExpiredInvitationsAfter, result => result.ExpiredInvitations, (result, count) => result with { ExpiredInvitations = result.ExpiredInvitations + count }),
        new("accepted_invitations", InvitationsTable, $"accepted_at IS NOT NULL AND accepted_at < {CutoffToken}", AcceptedAtColumn, options => options.RemoveAcceptedInvitationsAfter, result => result.AcceptedInvitations, (result, count) => result with { AcceptedInvitations = result.AcceptedInvitations + count }),
        new("revoked_invitations", InvitationsTable, $"revoked_at IS NOT NULL AND revoked_at < {CutoffToken}", RevokedAtColumn, options => options.RemoveRevokedInvitationsAfter, result => result.RevokedInvitations, (result, count) => result with { RevokedInvitations = result.RevokedInvitations + count }),
        new("expired_handshakes", HandshakesTable, $"expires_at < {CutoffToken} AND is_revoked = {FalseToken} AND is_completed = {FalseToken}", ExpiresAtColumn, options => options.RemoveExpiredHandshakesAfter, result => result.ExpiredHandshakes, (result, count) => result with { ExpiredHandshakes = result.ExpiredHandshakes + count }),
        new("completed_handshakes", HandshakesTable, $"is_completed = {TrueToken} AND completed_at IS NOT NULL AND completed_at < {CutoffToken}", CompletedAtColumn, options => options.RemoveCompletedHandshakesAfter, result => result.CompletedHandshakes, (result, count) => result with { CompletedHandshakes = result.CompletedHandshakes + count }),
        new("revoked_handshakes", HandshakesTable, $"is_revoked = {TrueToken} AND revoked_at IS NOT NULL AND revoked_at < {CutoffToken}", RevokedAtColumn, options => options.RemoveRevokedHandshakesAfter, result => result.RevokedHandshakes, (result, count) => result with { RevokedHandshakes = result.RevokedHandshakes + count }),
        new("expired_remembered_mfa_devices", RememberedMfaDevicesTable, $"expires_at < {CutoffToken} AND revoked_at IS NULL", ExpiresAtColumn, options => options.RemoveExpiredRememberedMfaDevicesAfter, result => result.ExpiredRememberedMfaDevices, (result, count) => result with { ExpiredRememberedMfaDevices = result.ExpiredRememberedMfaDevices + count }),
        new("revoked_remembered_mfa_devices", RememberedMfaDevicesTable, $"revoked_at IS NOT NULL AND revoked_at < {CutoffToken}", RevokedAtColumn, options => options.RemoveRevokedRememberedMfaDevicesAfter, result => result.RevokedRememberedMfaDevices, (result, count) => result with { RevokedRememberedMfaDevices = result.RevokedRememberedMfaDevices + count }),
        new("expired_rate_limits", RateLimitsTable, $"expires_at < {CutoffToken}", ExpiresAtColumn, options => options.RemoveExpiredRateLimitsAfter, result => result.ExpiredRateLimits, (result, count) => result with { ExpiredRateLimits = result.ExpiredRateLimits + count }),
        new("audit_events", SecurityEventsTable, $"occurred_at < {CutoffToken}", OccurredAtColumn, options => options.RemoveAuditEventsAfter, result => result.AuditEvents, (result, count) => result with { AuditEvents = result.AuditEvents + count }),
        new("sent_emails", EmailOutboxTable, $"sensitivity = '{NormalEmailSensitivity}' AND sent_at IS NOT NULL AND sent_at < {CutoffToken}", SentAtColumn, options => options.RemoveSentEmailsAfter, result => result.SentEmails, (result, count) => result with { SentEmails = result.SentEmails + count }),
        new("failed_emails", EmailOutboxTable, $"sensitivity = '{NormalEmailSensitivity}' AND failed_at IS NOT NULL AND discarded_at IS NULL AND failed_at < {CutoffToken}", FailedAtColumn, options => options.RemoveFailedEmailsAfter, result => result.FailedEmails, (result, count) => result with { FailedEmails = result.FailedEmails + count }),
        new("sent_sensitive_emails", EmailOutboxTable, $"(sensitivity IS NULL OR sensitivity <> '{NormalEmailSensitivity}') AND sent_at IS NOT NULL AND sent_at < {CutoffToken}", SentAtColumn, options => options.RemoveSentSensitiveEmailsAfter, result => result.SentSensitiveEmails, (result, count) => result with { SentSensitiveEmails = result.SentSensitiveEmails + count }),
        new("failed_sensitive_emails", EmailOutboxTable, $"(sensitivity IS NULL OR sensitivity <> '{NormalEmailSensitivity}') AND failed_at IS NOT NULL AND discarded_at IS NULL AND failed_at < {CutoffToken}", FailedAtColumn, options => options.RemoveFailedSensitiveEmailsAfter, result => result.FailedSensitiveEmails, (result, count) => result with { FailedSensitiveEmails = result.FailedSensitiveEmails + count }),
        new("discarded_emails", EmailOutboxTable, $"sensitivity = '{NormalEmailSensitivity}' AND discarded_at IS NOT NULL AND discarded_at < {CutoffToken}", DiscardedAtColumn, options => options.RemoveDiscardedEmailsAfter, result => result.DiscardedEmails, (result, count) => result with { DiscardedEmails = result.DiscardedEmails + count }),
        new("discarded_sensitive_emails", EmailOutboxTable, $"(sensitivity IS NULL OR sensitivity <> '{NormalEmailSensitivity}') AND discarded_at IS NOT NULL AND discarded_at < {CutoffToken}", DiscardedAtColumn, options => options.RemoveDiscardedSensitiveEmailsAfter, result => result.DiscardedSensitiveEmails, (result, count) => result with { DiscardedSensitiveEmails = result.DiscardedSensitiveEmails + count }),
        new("sent_security_event_webhooks", SecurityEventWebhookOutboxTable, $"sent_at IS NOT NULL AND sent_at < {CutoffToken}", SentAtColumn, options => options.RemoveSentSecurityEventWebhooksAfter, result => result.SentSecurityEventWebhooks, (result, count) => result with { SentSecurityEventWebhooks = result.SentSecurityEventWebhooks + count }),
        new("failed_security_event_webhooks", SecurityEventWebhookOutboxTable, $"failed_at IS NOT NULL AND discarded_at IS NULL AND failed_at < {CutoffToken}", FailedAtColumn, options => options.RemoveFailedSecurityEventWebhooksAfter, result => result.FailedSecurityEventWebhooks, (result, count) => result with { FailedSecurityEventWebhooks = result.FailedSecurityEventWebhooks + count }),
        new("discarded_security_event_webhooks", SecurityEventWebhookOutboxTable, $"discarded_at IS NOT NULL AND discarded_at < {CutoffToken}", DiscardedAtColumn, options => options.RemoveDiscardedSecurityEventWebhooksAfter, result => result.DiscardedSecurityEventWebhooks, (result, count) => result with { DiscardedSecurityEventWebhooks = result.DiscardedSecurityEventWebhooks + count }),
        new("expired_authorization_grants", AuthorizationGrantsTable, $"expires_at IS NOT NULL AND expires_at < {CutoffToken} AND revoked_at IS NULL", ExpiresAtColumn, options => options.RemoveExpiredAuthorizationGrantsAfter, result => result.ExpiredAuthorizationGrants, (result, count) => result with { ExpiredAuthorizationGrants = result.ExpiredAuthorizationGrants + count }),
        new("revoked_authorization_grants", AuthorizationGrantsTable, $"revoked_at IS NOT NULL AND revoked_at < {CutoffToken}", RevokedAtColumn, options => options.RemoveRevokedAuthorizationGrantsAfter, result => result.RevokedAuthorizationGrants, (result, count) => result with { RevokedAuthorizationGrants = result.RevokedAuthorizationGrants + count }),
        new("expired_passkey_challenges", PasskeyChallengesTable, $"expires_at < {CutoffToken} AND consumed_at IS NULL", ExpiresAtColumn, options => options.RemoveExpiredPasskeyChallengesAfter, result => result.ExpiredPasskeyChallenges, (result, count) => result with { ExpiredPasskeyChallenges = result.ExpiredPasskeyChallenges + count }),
        new("consumed_passkey_challenges", PasskeyChallengesTable, $"consumed_at IS NOT NULL AND consumed_at < {CutoffToken}", ConsumedAtColumn, options => options.RemoveConsumedPasskeyChallengesAfter, result => result.ConsumedPasskeyChallenges, (result, count) => result with { ConsumedPasskeyChallenges = result.ConsumedPasskeyChallenges + count })
    ];

    /// <summary>
    /// Runs the shared Ashlar cleanup plan with a provider-specific delete callback.
    /// </summary>
    /// <typeparam name="TContext">Provider-specific execution context type.</typeparam>
    /// <param name="options">Configured retention windows, batch sizes, and cleanup toggles.</param>
    /// <param name="now">UTC time used to calculate retention cutoffs.</param>
    /// <param name="context">Provider-specific execution context used to render and execute cleanup deletes.</param>
    /// <param name="deleteAsync">Provider-specific bounded delete callback.</param>
    /// <param name="createDefinition">Provider-specific renderer for cleanup delete definitions.</param>
    /// <param name="cancellationToken">Token for aborting cleanup work.</param>
    /// <returns>Number of rows deleted in each cleanup category.</returns>
    public static async Task<AshlarCleanupResult> RunAsync<TContext>(
        AshlarCleanupOptions options,
        DateTimeOffset now,
        TContext context,
        Func<TContext, AshlarCleanupDeleteDefinition, DateTimeOffset, CancellationToken, Task<int>> deleteAsync,
        Func<AshlarCleanupCategoryDefinition, AshlarCleanupDeleteDefinition> createDefinition,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(deleteAsync);
        ArgumentNullException.ThrowIfNull(createDefinition);

        var result = AshlarCleanupResult.Empty;
        var activeDefinitions = CategoryDefinitions;

        for (var batchNumber = 0; batchNumber < options.MaxBatchesPerRun && activeDefinitions.Length > 0; batchNumber++)
        {
            var batchResult = AshlarCleanupResult.Empty;
            foreach (var category in activeDefinitions)
            {
                var retention = category.Retention(options);
                if (retention == null)
                {
                    continue;
                }

                var deleted = await deleteAsync(context, createDefinition(category), now - retention.Value, cancellationToken);
                batchResult = category.AddCount(batchResult, deleted);
            }

            result = result.Add(batchResult);
            activeDefinitions = CategoryDefinitions
                .Where(category => category.GetCount(batchResult) == options.BatchSize)
                .ToArray();
        }

        return result;
    }

    /// <summary>
    /// Counts enabled and disabled cleanup categories for the provided options.
    /// </summary>
    /// <param name="options">Configured retention windows and cleanup toggles to inspect.</param>
    /// <returns>Enabled and disabled cleanup category counts.</returns>
    public static (int EnabledCategoryCount, int DisabledCategoryCount) CountCategories(AshlarCleanupOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var enabled = CategoryDefinitions.Count(category => category.Retention(options) != null);
        return (enabled, CategoryDefinitions.Length - enabled);
    }

    /// <summary>
    /// Renders a provider-neutral predicate template for a database provider.
    /// </summary>
    /// <param name="template">Provider-neutral predicate template to render.</param>
    /// <param name="cutoffParameter">Provider-specific parameter token used for the retention cutoff.</param>
    /// <param name="trueLiteral">The provider-specific boolean <see langword="true" /> literal.</param>
    /// <param name="falseLiteral">The provider-specific boolean <see langword="false" /> literal.</param>
    /// <returns>Rendered provider-specific predicate.</returns>
    public static string RenderPredicate(string template, string cutoffParameter, string trueLiteral, string falseLiteral)
    {
        return template
            .Replace(CutoffToken, cutoffParameter, StringComparison.Ordinal)
            .Replace(TrueToken, trueLiteral, StringComparison.Ordinal)
            .Replace(FalseToken, falseLiteral, StringComparison.Ordinal);
    }
}
