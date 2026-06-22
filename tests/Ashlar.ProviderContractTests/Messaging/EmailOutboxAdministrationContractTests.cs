using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.ProviderContractTests.Messaging;

internal abstract class EmailOutboxAdministrationContractTests : ProviderContractFixture
{
    protected static readonly DateTimeOffset AdminNow = new(2026, 6, 14, 12, 0, 0, TimeSpan.Zero);

    protected abstract Task<Guid> SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow row);

    protected abstract Task<EmailOutboxAdminRowState> ReadEmailOutboxAdminRowStateAsync(Guid id);

    [Test]
    public async Task SearchAndGetExposeSafeProviderNeutralProjection()
    {
        await SeedEmailOutboxAdminRowsAsync();
        await using var scope = CreateAsyncScope();
        var admin = GetEmailOutboxAdministration(scope.ServiceProvider);

        var page = await admin.SearchAsync(new EmailOutboxSearchRequest { Limit = 2, Offset = 1 });
        var failed = await admin.SearchAsync(new EmailOutboxSearchRequest
        {
            Statuses = new HashSet<EmailOutboxStatus> { EmailOutboxStatus.Failed },
            Limit = 10
        });
        var failedSummary = failed.Items.Single();
        var failedDetail = await admin.GetAsync(failedSummary.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(page.Items, Has.Count.EqualTo(2));
            Assert.That(page.HasMore, Is.True);
            Assert.That(page.Items.Select(entry => entry.Status), Is.EqualTo(new[] { EmailOutboxStatus.Scheduled, EmailOutboxStatus.Locked }));
            Assert.That(failedSummary.LastErrorSummary, Is.EqualTo("delivery failure"));
            Assert.That(failedDetail, Is.Not.Null);
            Assert.That(failedDetail!.FromAddress, Is.EqualTo("sender@example.com"));
            Assert.That(failedDetail.ReplyToAddress, Is.EqualTo("reply@example.com"));
            Assert.That(failedDetail.CcAddress, Is.EqualTo("cc@example.com"));
            Assert.That(failedDetail!.HasTextBody, Is.True);
            Assert.That(failedDetail.HasHtmlBody, Is.False);
        }
    }

    [Test]
    public async Task SensitiveSearchAndGetSuppressFailureAndMessageFields()
    {
        var sensitive = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed(
            toAddress: "sensitive@example.com",
            subject: "Reset token",
            textBody: "live-token",
            sensitivity: nameof(EmailMessageSensitivity.ContainsLiveSecret),
            bodyProtection: nameof(EmailOutboxBodyProtection.SecretProtector),
            lastError: "failed with live-token"));
        await using var scope = CreateAsyncScope();
        var admin = GetEmailOutboxAdministration(scope.ServiceProvider);

        var detail = await admin.GetAsync(sensitive);
        var failed = await admin.SearchAsync(new EmailOutboxSearchRequest
        {
            Statuses = new HashSet<EmailOutboxStatus> { EmailOutboxStatus.Failed },
            Limit = 10
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(detail, Is.Not.Null);
            Assert.That(detail!.ToAddress, Is.Null);
            Assert.That(detail.Subject, Is.Null);
            Assert.That(detail.LastErrorSummary, Is.EqualTo(EmailOutboxAdministrationProvider.SensitiveFailureSummary));
            Assert.That(failed.Items.Single().LastErrorSummary, Does.Not.Contain("live-token"));
        }
    }

    [Test]
    public async Task RetryAndDiscardOperateOnlyOnTerminalFailedRows()
    {
        var failed = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("failed@example.com"));
        var pending = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Pending("pending@example.com"));
        var sent = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Sent("sent@example.com"));
        var retryable = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Retryable("retryable@example.com"));
        var discarded = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Discarded("discarded@example.com"));
        var sensitiveRetry = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed(
            toAddress: "sensitive-retry@example.com",
            subject: "Reset token",
            sensitivity: nameof(EmailMessageSensitivity.ContainsLiveSecret),
            bodyProtection: nameof(EmailOutboxBodyProtection.SecretProtector)));
        var sensitiveDiscard = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed(
            toAddress: "sensitive-discard@example.com",
            subject: "Reset token",
            sensitivity: nameof(EmailMessageSensitivity.ContainsLiveSecret),
            bodyProtection: nameof(EmailOutboxBodyProtection.SecretProtector)));
        await using var scope = CreateAsyncScope();
        var admin = GetEmailOutboxAdministration(scope.ServiceProvider);

        var missingRetry = await admin.RetryAsync(CreateOperationRequest(Guid.NewGuid()));
        var missingDiscard = await admin.DiscardAsync(CreateOperationRequest(Guid.NewGuid()));
        var retry = await admin.RetryAsync(CreateOperationRequest(failed));
        var retriedState = await ReadEmailOutboxAdminRowStateAsync(failed);
        var retriedRetry = await admin.RetryAsync(CreateOperationRequest(failed));
        var retriedDiscard = await admin.DiscardAsync(CreateOperationRequest(failed));
        var pendingRetry = await admin.RetryAsync(CreateOperationRequest(pending));
        var sentRetry = await admin.RetryAsync(CreateOperationRequest(sent));
        var retryableDiscard = await admin.DiscardAsync(CreateOperationRequest(retryable));
        var discardedRetry = await admin.RetryAsync(CreateOperationRequest(discarded));
        var discardedDiscard = await admin.DiscardAsync(CreateOperationRequest(discarded));
        var sensitiveRetryResult = await admin.RetryAsync(CreateOperationRequest(sensitiveRetry));
        var sensitiveDiscardResult = await admin.DiscardAsync(CreateOperationRequest(sensitiveDiscard));
        var failedAgain = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("discard@example.com"));
        var discard = await admin.DiscardAsync(CreateOperationRequest(failedAgain));
        var discardedState = await ReadEmailOutboxAdminRowStateAsync(failedAgain);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingRetry.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFound));
            Assert.That(missingDiscard.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFound));
            Assert.That(retry.Status, Is.EqualTo(EmailOutboxOperationStatus.Retried));
            Assert.That(retriedState.FailedAt, Is.Null);
            Assert.That(retriedState.LastError, Is.Null);
            Assert.That(retriedState.LockedBy, Is.Null);
            Assert.That(retriedState.LockedUntil, Is.Null);
            Assert.That(retriedState.AvailableAt, Is.EqualTo(AdminNow));
            Assert.That(retriedRetry.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFailed));
            Assert.That(retriedDiscard.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFailed));
            Assert.That(pendingRetry.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFailed));
            Assert.That(sentRetry.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFailed));
            Assert.That(retryableDiscard.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFailed));
            Assert.That(discardedRetry.Status, Is.EqualTo(EmailOutboxOperationStatus.AlreadyDiscarded));
            Assert.That(discardedDiscard.Status, Is.EqualTo(EmailOutboxOperationStatus.AlreadyDiscarded));
            Assert.That(sensitiveRetryResult.Status, Is.EqualTo(EmailOutboxOperationStatus.Retried));
            Assert.That(sensitiveRetryResult.ToAddress, Is.Null);
            Assert.That(sensitiveRetryResult.Subject, Is.Null);
            Assert.That(sensitiveDiscardResult.Status, Is.EqualTo(EmailOutboxOperationStatus.Discarded));
            Assert.That(sensitiveDiscardResult.ToAddress, Is.Null);
            Assert.That(sensitiveDiscardResult.Subject, Is.Null);
            Assert.That(discard.Status, Is.EqualTo(EmailOutboxOperationStatus.Discarded));
            Assert.That(discardedState.DiscardedAt, Is.EqualTo(AdminNow));
            Assert.That(discardedState.LockedBy, Is.Null);
            Assert.That(discardedState.LockedUntil, Is.Null);
        }
    }

    private async Task SeedEmailOutboxAdminRowsAsync()
    {
        await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Pending("pending@example.com", createdAt: AdminNow.AddMinutes(-5), availableAt: AdminNow.AddMinutes(-5)));
        await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Pending("scheduled@example.com", createdAt: AdminNow.AddMinutes(-4), availableAt: AdminNow.AddMinutes(30)));
        await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Locked("locked@example.com", AdminNow.AddMinutes(5), createdAt: AdminNow.AddMinutes(-3)));
        await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Locked("expired@example.com", AdminNow.AddMinutes(-1), createdAt: AdminNow.AddMinutes(-2)));
        await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("failed@example.com", failedAt: AdminNow.AddSeconds(-30), createdAt: AdminNow.AddMinutes(-1), lastError: "delivery failure"));
        await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Sent("sent@example.com"));
        await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Discarded("discarded@example.com"));
    }

    private static IEmailOutboxAdministrationService GetEmailOutboxAdministration(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IEmailOutboxAdministrationService>();
    }

    private static EmailOutboxOperationRequest CreateOperationRequest(Guid id)
    {
        return new EmailOutboxOperationRequest(id, new AuditContext(Guid.NewGuid(), "203.0.113.9", "agent", "corr"));
    }

    protected sealed record SeedEmailOutboxAdminRow(
        string ToAddress,
        string Subject,
        string? TextBody,
        string? HtmlBody,
        string Sensitivity,
        string BodyProtection,
        DateTimeOffset CreatedAt,
        DateTimeOffset AvailableAt,
        DateTimeOffset? SentAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        int AttemptCount,
        string? LastError,
        string? FromAddress = "sender@example.com",
        string? ReplyToAddress = "reply@example.com",
        string? CcAddress = "cc@example.com")
    {
        public Guid Id { get; } = Guid.NewGuid();

        public static SeedEmailOutboxAdminRow Pending(
            string toAddress,
            string subject = "Subject",
            string? textBody = "Body",
            string? htmlBody = null,
            DateTimeOffset? createdAt = null,
            DateTimeOffset? availableAt = null,
            string sensitivity = nameof(EmailMessageSensitivity.Normal),
            string bodyProtection = nameof(EmailOutboxBodyProtection.None),
            string? lockedBy = null,
            DateTimeOffset? lockedUntil = null)
        {
            return new SeedEmailOutboxAdminRow(
                toAddress,
                subject,
                textBody,
                htmlBody,
                sensitivity,
                bodyProtection,
                createdAt ?? AdminNow,
                availableAt ?? AdminNow,
                null,
                null,
                null,
                lockedBy,
                lockedUntil,
                0,
                null);
        }

        public static SeedEmailOutboxAdminRow Locked(string toAddress, DateTimeOffset lockedUntil, DateTimeOffset? createdAt = null)
        {
            return Pending(toAddress, createdAt: createdAt, lockedBy: "worker", lockedUntil: lockedUntil);
        }

        public static SeedEmailOutboxAdminRow Failed(
            string toAddress,
            string subject = "Subject",
            string? textBody = "Body",
            string? htmlBody = null,
            DateTimeOffset? createdAt = null,
            DateTimeOffset? availableAt = null,
            DateTimeOffset? failedAt = null,
            string sensitivity = nameof(EmailMessageSensitivity.Normal),
            string bodyProtection = nameof(EmailOutboxBodyProtection.None),
            string? lastError = "failure")
        {
            return new SeedEmailOutboxAdminRow(
                toAddress,
                subject,
                textBody,
                htmlBody,
                sensitivity,
                bodyProtection,
                createdAt ?? AdminNow,
                availableAt ?? AdminNow,
                null,
                failedAt ?? AdminNow.AddMinutes(-1),
                null,
                null,
                null,
                3,
                lastError);
        }

        public static SeedEmailOutboxAdminRow Sent(string toAddress)
        {
            return new SeedEmailOutboxAdminRow(toAddress, "Subject", "Body", null, nameof(EmailMessageSensitivity.Normal), nameof(EmailOutboxBodyProtection.None), AdminNow, AdminNow, AdminNow, null, null, null, null, 1, null);
        }

        public static SeedEmailOutboxAdminRow Retryable(string toAddress)
        {
            return new SeedEmailOutboxAdminRow(toAddress, "Subject", "Body", null, nameof(EmailMessageSensitivity.Normal), nameof(EmailOutboxBodyProtection.None), AdminNow, AdminNow, null, null, null, null, null, 1, null);
        }

        public static SeedEmailOutboxAdminRow Discarded(string toAddress)
        {
            return new SeedEmailOutboxAdminRow(toAddress, "Subject", "Body", null, nameof(EmailMessageSensitivity.Normal), nameof(EmailOutboxBodyProtection.None), AdminNow, AdminNow, null, AdminNow.AddMinutes(-1), AdminNow, null, null, 3, "discarded");
        }
    }

    protected sealed record EmailOutboxAdminRowState(
        DateTimeOffset AvailableAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        string? LastError);
}
