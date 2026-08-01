using Ashlar.Operational;

namespace Ashlar.ProviderContractTests.Operational;

/// <summary>Verifies retention boundaries, deletion counts, batching, disabled categories, and transactional cleanup.</summary>
public abstract class AshlarCleanupServiceContractTests : ProviderContractFixture
{
    /// <summary>Seeds expired terminal rows alongside recent or active rows in every cleanup category.</summary>
    protected abstract Task SeedMixedCleanupRowsAsync();

    /// <summary>Seeds the requested number of sessions beyond their retention threshold.</summary>
    /// <param name="count">Number of rows to seed.</param>
    protected abstract Task SeedExpiredSessionsAsync(int count);

    /// <summary>Seeds one audit event beyond its retention threshold.</summary>
    protected abstract Task SeedOldAuditEventAsync();

    /// <summary>Seeds expired and revoked remembered devices beyond their retention thresholds.</summary>
    protected abstract Task SeedOldRememberedMfaDevicesAsync();

    /// <summary>Seeds sensitive and normal emails across old, recent, active, and terminal states.</summary>
    protected abstract Task SeedSensitiveEmailCleanupRowsAsync();

    /// <summary>Counts every row currently stored in a provider table.</summary>
    /// <param name="tableName">Provider table whose rows are counted.</param>
    /// <returns>The number of rows in the table.</returns>
    protected abstract Task<int> CountRowsAsync(string tableName);

    /// <summary>Counts stored email rows whose subject exactly matches the supplied value.</summary>
    /// <param name="subject">Subject stored with the seeded email.</param>
    /// <returns>The number of email rows with the subject.</returns>
    protected abstract Task<int> CountEmailRowsBySubjectAsync(string subject);

    /// <summary>Runs cleanup with audit-event retention disabled.</summary>
    /// <returns>The cleanup counts reported with audit retention disabled.</returns>
    protected abstract Task<AshlarCleanupResult> RunCleanupWithNullAuditRetentionAsync();

    /// <summary>Runs cleanup with both remembered-device retention periods disabled.</summary>
    /// <returns>The cleanup counts reported with remembered-device retention disabled.</returns>
    protected abstract Task<AshlarCleanupResult> RunCleanupWithNullRememberedMfaDeviceRetentionsAsync();

    /// <summary>Runs cleanup with normal and sensitive discarded-email retention disabled.</summary>
    /// <returns>The cleanup counts reported with email-discard retention disabled.</returns>
    protected abstract Task<AshlarCleanupResult> RunCleanupWithNullEmailDiscardRetentionAsync();

    /// <summary>Runs one cleanup pass using the fixture's configured retention periods and batch size.</summary>
    /// <param name="serviceProvider">Scoped services participating in the contract operation.</param>
    /// <returns>The cleanup counts reported by the provider.</returns>
    protected abstract Task<AshlarCleanupResult> RunCleanupAsync(IServiceProvider serviceProvider);

    /// <summary>Whether the provider can verify cleanup rollback.</summary>
    protected virtual bool SupportsCleanupTransactionRollback => false;

    /// <summary>Reports an empty result when no retained data exists, without inventing deleted rows.</summary>
    [Test]
    public async Task CleanupAsyncOnEmptyDatabaseReturnsZeroCounts()
    {
        var result = await RunCleanupWithNullAuditRetentionAsync();

        Assert.That(result, Is.EqualTo(AshlarCleanupResult.Empty));
    }

    /// <summary>Deletes expired terminal rows, preserves recent or active rows, and reports each deletion category accurately.</summary>
    [Test]
    public async Task CleanupAsyncRemovesOnlyRowsOlderThanRetentionThresholdsAndReturnsCategoryCounts()
    {
        await SeedMixedCleanupRowsAsync();
        await using var scope = CreateAsyncScope();

        var result = await RunCleanupAsync(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.ExpiredSessions, Is.EqualTo(1));
            Assert.That(result.RevokedSessions, Is.EqualTo(1));
            Assert.That(result.ExpiredCredentials, Is.EqualTo(1));
            Assert.That(result.RevokedCredentials, Is.EqualTo(1));
            Assert.That(result.ExpiredAuthorizationGrants, Is.EqualTo(1));
            Assert.That(result.RevokedAuthorizationGrants, Is.EqualTo(1));
            Assert.That(result.ExpiredInvitations, Is.EqualTo(1));
            Assert.That(result.AcceptedInvitations, Is.EqualTo(1));
            Assert.That(result.RevokedInvitations, Is.EqualTo(1));
            Assert.That(result.ExpiredHandshakes, Is.EqualTo(1));
            Assert.That(result.CompletedHandshakes, Is.EqualTo(1));
            Assert.That(result.RevokedHandshakes, Is.EqualTo(1));
            Assert.That(result.ExpiredRememberedMfaDevices, Is.EqualTo(1));
            Assert.That(result.RevokedRememberedMfaDevices, Is.EqualTo(1));
            Assert.That(result.ExpiredRateLimits, Is.EqualTo(1));
            Assert.That(result.ExpiredPasskeyChallenges, Is.EqualTo(1));
            Assert.That(result.ConsumedPasskeyChallenges, Is.EqualTo(1));
            Assert.That(result.AuditEvents, Is.EqualTo(1));
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await CountRowsAsync("ashlar_sessions"), Is.EqualTo(2));
            Assert.That(await CountRowsAsync("ashlar_credentials"), Is.EqualTo(2));
            Assert.That(await CountRowsAsync("ashlar_authorization_grants"), Is.EqualTo(2));
            Assert.That(await CountRowsAsync("ashlar_invitations"), Is.EqualTo(3));
            Assert.That(await CountRowsAsync("ashlar_mfa_handshakes"), Is.EqualTo(3));
            Assert.That(await CountRowsAsync("ashlar_remembered_mfa_devices"), Is.EqualTo(2));
            Assert.That(await CountRowsAsync("ashlar_rate_limits"), Is.EqualTo(1));
            Assert.That(await CountRowsAsync("ashlar_passkey_challenges"), Is.EqualTo(2));
            Assert.That(await CountRowsAsync("ashlar_security_events"), Is.EqualTo(1));
        }
    }

    /// <summary>Limits each cleanup pass to its batch size while allowing later passes to drain the backlog.</summary>
    [Test]
    public async Task CleanupAsyncRespectsBatchSizeAndRepeatedCleanupCompletesRemainingRows()
    {
        await SeedExpiredSessionsAsync(3);
        await using var scope = CreateAsyncScope();
        var first = await RunCleanupAsync(scope.ServiceProvider);
        var second = await RunCleanupAsync(scope.ServiceProvider);
        var third = await RunCleanupAsync(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.ExpiredSessions, Is.EqualTo(2));
            Assert.That(second.ExpiredSessions, Is.EqualTo(1));
            Assert.That(third.ExpiredSessions, Is.Zero);
            Assert.That(await CountRowsAsync("ashlar_sessions"), Is.Zero);
        }
    }

    /// <summary>Preserves audit events when their retention period is disabled.</summary>
    [Test]
    public async Task CleanupAsyncSkipsCategoriesWithNullRetention()
    {
        await SeedOldAuditEventAsync();

        var result = await RunCleanupWithNullAuditRetentionAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.AuditEvents, Is.Zero);
            Assert.That(await CountRowsAsync("ashlar_security_events"), Is.EqualTo(1));
        }
    }

    /// <summary>Preserves both expired and revoked remembered devices when their retention periods are disabled.</summary>
    [Test]
    public async Task CleanupAsyncSkipsRememberedMfaDeviceCategoriesWithNullRetention()
    {
        await SeedOldRememberedMfaDevicesAsync();

        var result = await RunCleanupWithNullRememberedMfaDeviceRetentionsAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.ExpiredRememberedMfaDevices, Is.Zero);
            Assert.That(result.RevokedRememberedMfaDevices, Is.Zero);
            Assert.That(await CountRowsAsync("ashlar_remembered_mfa_devices"), Is.EqualTo(2));
        }
    }

    /// <summary>Applies sensitive-email retention independently while preserving normal, recent, pending, and locked messages.</summary>
    [Test]
    public async Task CleanupAsyncUsesSeparateRetentionForSensitiveTerminalEmailRows()
    {
        await SeedSensitiveEmailCleanupRowsAsync();
        await using var scope = CreateAsyncScope();

        var result = await RunCleanupAsync(scope.ServiceProvider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.SentSensitiveEmails, Is.EqualTo(1));
            Assert.That(result.FailedSensitiveEmails, Is.EqualTo(1));
            Assert.That(result.DiscardedSensitiveEmails, Is.EqualTo(1));
            Assert.That(result.SentEmails, Is.Zero);
            Assert.That(result.FailedEmails, Is.Zero);
            Assert.That(result.DiscardedEmails, Is.Zero);
            Assert.That(await CountEmailRowsBySubjectAsync("sensitive-old-sent"), Is.Zero);
            Assert.That(await CountEmailRowsBySubjectAsync("sensitive-old-failed"), Is.Zero);
            Assert.That(await CountEmailRowsBySubjectAsync("sensitive-old-discarded"), Is.Zero);
            Assert.That(await CountEmailRowsBySubjectAsync("sensitive-recent-sent"), Is.EqualTo(1));
            Assert.That(await CountEmailRowsBySubjectAsync("sensitive-recent-failed"), Is.EqualTo(1));
            Assert.That(await CountEmailRowsBySubjectAsync("sensitive-recent-discarded"), Is.EqualTo(1));
            Assert.That(await CountEmailRowsBySubjectAsync("normal-old-sent"), Is.EqualTo(1));
            Assert.That(await CountEmailRowsBySubjectAsync("normal-old-failed"), Is.EqualTo(1));
            Assert.That(await CountEmailRowsBySubjectAsync("normal-old-discarded"), Is.EqualTo(1));
            Assert.That(await CountEmailRowsBySubjectAsync("sensitive-pending"), Is.EqualTo(1));
            Assert.That(await CountEmailRowsBySubjectAsync("sensitive-locked"), Is.EqualTo(1));
        }
    }

    /// <summary>Preserves discarded normal and sensitive emails when discard retention is disabled.</summary>
    [Test]
    public async Task CleanupAsyncSkipsDiscardedEmailCategoriesWithNullRetention()
    {
        await SeedSensitiveEmailCleanupRowsAsync();

        var result = await RunCleanupWithNullEmailDiscardRetentionAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.DiscardedEmails, Is.Zero);
            Assert.That(result.DiscardedSensitiveEmails, Is.Zero);
            Assert.That(await CountEmailRowsBySubjectAsync("sensitive-old-discarded"), Is.EqualTo(1));
            Assert.That(await CountEmailRowsBySubjectAsync("normal-old-discarded"), Is.EqualTo(1));
        }
    }


    /// <summary>Restores deleted rows when a transactional cleanup operation is rolled back.</summary>
    /// <exception cref="System.InvalidOperationException">The fixture did not register a transaction provider.</exception>
    [Test]
    public async Task CleanupAsyncRollsBackWhenProviderImplementationParticipatesInAshlarTransactions()
    {
        if (!SupportsCleanupTransactionRollback)
        {
            Assert.Ignore("This provider cleanup service does not participate in IAshlarTransactionProvider transactions.");
        }

        await SeedExpiredSessionsAsync(1);
        await using var scope = CreateAsyncScope();
        var transactionProvider = GetTransactionProvider(scope.ServiceProvider) ?? throw new InvalidOperationException("Transaction provider is not registered.");

        await using (var transaction = await transactionProvider.BeginTransactionAsync())
        {
            var result = await RunCleanupAsync(scope.ServiceProvider);
            Assert.That(result.ExpiredSessions, Is.EqualTo(1));
            await transaction.RollbackAsync();
        }

        Assert.That(await CountRowsAsync("ashlar_sessions"), Is.EqualTo(1));
    }
}
