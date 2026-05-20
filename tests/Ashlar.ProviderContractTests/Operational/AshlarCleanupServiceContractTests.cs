using Ashlar.Operational;

namespace Ashlar.ProviderContractTests.Operational;

internal abstract class AshlarCleanupServiceContractTests : ProviderContractFixture
{
    protected abstract Task SeedMixedCleanupRowsAsync();

    protected abstract Task SeedExpiredSessionsAsync(int count);

    protected abstract Task SeedOldAuditEventAsync();

    protected abstract Task<int> CountRowsAsync(string tableName);

    protected abstract Task<AshlarCleanupResult> RunCleanupWithNullAuditRetentionAsync();

    protected virtual bool SupportsCleanupTransactionRollback => false;

    [Test]
    public async Task CleanupAsyncOnEmptyDatabaseReturnsZeroCounts()
    {
        var result = await RunCleanupWithNullAuditRetentionAsync();

        Assert.That(result, Is.EqualTo(AshlarCleanupResult.Empty));
    }

    [Test]
    public async Task CleanupAsyncRemovesOnlyRowsOlderThanRetentionThresholdsAndReturnsCategoryCounts()
    {
        await SeedMixedCleanupRowsAsync();
        await using var scope = CreateAsyncScope();

        var result = await GetCleanupService(scope.ServiceProvider).CleanupAsync();

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
            Assert.That(await CountRowsAsync("ashlar_rate_limits"), Is.EqualTo(1));
            Assert.That(await CountRowsAsync("ashlar_passkey_challenges"), Is.EqualTo(2));
            Assert.That(await CountRowsAsync("ashlar_security_events"), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CleanupAsyncRespectsBatchSizeAndRepeatedCleanupCompletesRemainingRows()
    {
        await SeedExpiredSessionsAsync(3);
        await using var scope = CreateAsyncScope();
        var cleanup = GetCleanupService(scope.ServiceProvider);

        var first = await cleanup.CleanupAsync();
        var second = await cleanup.CleanupAsync();
        var third = await cleanup.CleanupAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.ExpiredSessions, Is.EqualTo(2));
            Assert.That(second.ExpiredSessions, Is.EqualTo(1));
            Assert.That(third.ExpiredSessions, Is.Zero);
            Assert.That(await CountRowsAsync("ashlar_sessions"), Is.Zero);
        }
    }

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
            var result = await GetCleanupService(scope.ServiceProvider).CleanupAsync();
            Assert.That(result.ExpiredSessions, Is.EqualTo(1));
            await transaction.RollbackAsync();
        }

        Assert.That(await CountRowsAsync("ashlar_sessions"), Is.EqualTo(1));
    }
}


