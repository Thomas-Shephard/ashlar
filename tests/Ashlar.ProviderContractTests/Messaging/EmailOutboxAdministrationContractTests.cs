using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection;
using Ashlar.Identity.Abstractions.Services;

namespace Ashlar.ProviderContractTests.Messaging;

/// <summary>Verifies safe browsing, sensitive-data redaction, and valid retry and discard transitions.</summary>
public abstract class EmailOutboxAdministrationContractTests : ProviderContractFixture
{
    /// <summary>Fixed timestamp used to create deterministic provider rows.</summary>
    protected static readonly DateTimeOffset AdminNow = new(2026, 6, 14, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Persists the supplied provider-neutral email state and returns its identifier.</summary>
    /// <param name="row">Provider-neutral state to persist before the assertion.</param>
    /// <returns>The identifier assigned to the seeded row.</returns>
    protected abstract Task<Guid> SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow row);

    /// <summary>Reads delivery timing, lock, discard, and safe error state for the requested email.</summary>
    /// <param name="id">Identifier of the seeded row.</param>
    /// <returns>The persisted state of the requested row.</returns>
    protected abstract Task<EmailOutboxAdminRowState> ReadEmailOutboxAdminRowStateAsync(Guid id);

    /// <summary>Returns stable public statuses and sanitized failure details through both search and lookup.</summary>
    [Test]
    public async Task SearchAndGetExposeSafeProviderNeutralProjection()
    {
        await SeedEmailOutboxAdminRowsAsync();
        await using var scope = CreateAsyncScope();
        var admin = GetEmailOutboxAdministration(scope.ServiceProvider);
        var actor = await CreateActorAsync(scope.ServiceProvider);

        var page = await admin.SearchAsync(actor, OperationalAdministrationScope.Global, CreateSearchRequest() with { Limit = 2, Offset = 1 });
        var failed = await admin.SearchAsync(actor, OperationalAdministrationScope.Global, new EmailOutboxSearchRequest
        {
            Statuses = new HashSet<EmailOutboxStatus> { EmailOutboxStatus.Failed },
            Limit = 10
        });
        var failedSummary = failed.Items.Single();
        var failedDetail = await admin.GetAsync(actor, OperationalAdministrationScope.Global, new(failedSummary.Id));

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

    /// <summary>Hides recipient, subject, and secret-bearing failure text for sensitive messages.</summary>
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
        var actor = await CreateActorAsync(scope.ServiceProvider);

        var detail = await admin.GetAsync(actor, OperationalAdministrationScope.Global, new(sensitive));
        var failed = await admin.SearchAsync(actor, OperationalAdministrationScope.Global, new EmailOutboxSearchRequest
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

    /// <summary>Transitions only terminal failures, clears stale delivery state, and keeps sensitive details hidden.</summary>
    [Test]
    public async Task RetryAndDiscardOperateOnlyOnTerminalFailedRows()
    {
        var failed = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("failed@example.com"));
        var pending = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Pending("pending@example.com"));
        var scheduled = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Pending(
            "scheduled@example.com", availableAt: AdminNow.AddMinutes(5)));
        var locked = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Locked(
            "locked@example.com", AdminNow.AddMinutes(5)));
        var expiredLock = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Locked(
            "expired-lock@example.com", AdminNow.AddMinutes(-1)));
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
        var actor = await CreateActorAsync(
            scope.ServiceProvider, IAccountSecurityAdministrationService.ProofPurpose);

        var missingRetry = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(Guid.NewGuid()));
        var missingDiscard = await admin.DiscardAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(Guid.NewGuid()));
        var retry = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(failed));
        var retriedState = await ReadEmailOutboxAdminRowStateAsync(failed);
        var retriedRetry = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(failed));
        var retriedDiscard = await admin.DiscardAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(failed));
        var pendingRetry = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(pending));
        var scheduledRetry = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(scheduled));
        var lockedRetry = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(locked));
        var expiredLockRetry = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(expiredLock));
        var sentRetry = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(sent));
        var retryableDiscard = await admin.DiscardAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(retryable));
        var discardedRetry = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(discarded));
        var discardedDiscard = await admin.DiscardAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(discarded));
        var sensitiveRetryResult = await admin.RetryAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(sensitiveRetry));
        var sensitiveDiscardResult = await admin.DiscardAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(sensitiveDiscard));
        var failedAgain = await SeedEmailOutboxAdminRowAsync(SeedEmailOutboxAdminRow.Failed("discard@example.com"));
        var discard = await admin.DiscardAsync(actor, OperationalAdministrationScope.Global, CreateOperationRequest(failedAgain));
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
            Assert.That(pendingRetry.OutboxStatus, Is.EqualTo(EmailOutboxStatus.Pending));
            Assert.That(scheduledRetry.OutboxStatus, Is.EqualTo(EmailOutboxStatus.Scheduled));
            Assert.That(lockedRetry.OutboxStatus, Is.EqualTo(EmailOutboxStatus.Locked));
            Assert.That(expiredLockRetry.OutboxStatus, Is.EqualTo(EmailOutboxStatus.ExpiredLock));
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

    private static EmailOutboxSearchRequest CreateSearchRequest() => new();

    private static EmailOutboxOperationRequest CreateOperationRequest(Guid id)
    {
        return new EmailOutboxOperationRequest(id);
    }

    private static async Task<AccountSecurityActorContext> CreateActorAsync(
        IServiceProvider services,
        string purpose = AccountSecurityActorContext.AdministrationReadProofPurpose)
    {
        var user = await CreateUserAsync(GetUserRepository(services));
        var token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var session = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = HashToken(services, token),
            CreatedAt = AdminNow,
            AdditionalVerificationAt = AdminNow,
            ExpiresAt = AdminNow.AddYears(1)
        };
        return new AccountSecurityActorContext(user.Id, TenantContext.Global, session.Id,
            await CreateFreshMfaProofAsync(services, session, token, purpose),
            new AuditContext(user.Id, "203.0.113.9", "agent", "corr"));
    }

    /// <summary>Provider-neutral state used to seed an email outbox administration row.</summary>
    /// <param name="ToAddress">Email recipient.</param>
    /// <param name="Subject">Email subject.</param>
    /// <param name="TextBody">Plain-text body, if present.</param>
    /// <param name="HtmlBody">HTML body, if present.</param>
    /// <param name="Sensitivity">Data sensitivity classification.</param>
    /// <param name="BodyProtection">Protection applied to the stored bodies.</param>
    /// <param name="CreatedAt">Time the email was created.</param>
    /// <param name="AvailableAt">Time the email becomes eligible for dispatch.</param>
    /// <param name="SentAt">Successful-delivery time, if sent.</param>
    /// <param name="FailedAt">Terminal failure time, if failed.</param>
    /// <param name="DiscardedAt">Time further delivery was abandoned, if discarded.</param>
    /// <param name="LockedBy">Worker holding the dispatch lock, if locked.</param>
    /// <param name="LockedUntil">Time the dispatch lock expires, if locked.</param>
    /// <param name="AttemptCount">Number of delivery attempts.</param>
    /// <param name="LastError">Safe delivery failure detail, if present.</param>
    /// <param name="FromAddress">Sender address, if present.</param>
    /// <param name="ReplyToAddress">Reply-to address, if present.</param>
    /// <param name="CcAddress">Carbon-copy recipient, if present.</param>
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
        /// <summary>Unique email identifier persisted with this seeded row.</summary>
        public Guid Id { get; } = Guid.NewGuid();

        /// <summary>Creates a seeded email row with the supplied delivery state.</summary>
        /// <param name="toAddress">Recipient stored with the seeded email.</param>
        /// <param name="subject">Subject stored with the seeded email.</param>
        /// <param name="textBody">Plain-text message body to persist.</param>
        /// <param name="htmlBody">HTML message body to persist.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <param name="availableAt">Time from which the row is eligible for dispatch.</param>
        /// <param name="sensitivity">Data sensitivity classification to persist.</param>
        /// <param name="bodyProtection">Protection scheme recorded for stored bodies.</param>
        /// <param name="lockedBy">Worker identifier holding the dispatch lock.</param>
        /// <param name="lockedUntil">Time until which a worker owns the row.</param>
        /// <returns>A pending email row descriptor.</returns>
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

        /// <summary>Creates a locked row for provider-state assertions.</summary>
        /// <param name="toAddress">Recipient stored with the seeded email.</param>
        /// <param name="lockedUntil">Time until which a worker owns the row.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <returns>A locked email row descriptor.</returns>
        public static SeedEmailOutboxAdminRow Locked(string toAddress, DateTimeOffset lockedUntil, DateTimeOffset? createdAt = null)
        {
            return Pending(toAddress, createdAt: createdAt, lockedBy: "worker", lockedUntil: lockedUntil);
        }

        /// <summary>Creates a seeded email row with the supplied delivery state.</summary>
        /// <param name="toAddress">Recipient stored with the seeded email.</param>
        /// <param name="subject">Subject stored with the seeded email.</param>
        /// <param name="textBody">Plain-text message body to persist.</param>
        /// <param name="htmlBody">HTML message body to persist.</param>
        /// <param name="createdAt">Creation time to persist.</param>
        /// <param name="availableAt">Time from which the row is eligible for dispatch.</param>
        /// <param name="failedAt">Terminal failure time.</param>
        /// <param name="sensitivity">Data sensitivity classification to persist.</param>
        /// <param name="bodyProtection">Protection scheme recorded for stored bodies.</param>
        /// <param name="lastError">Safe persisted delivery failure detail.</param>
        /// <returns>A failed email row descriptor.</returns>
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

        /// <summary>Creates a sent row for provider-state assertions.</summary>
        /// <param name="toAddress">Recipient stored with the seeded email.</param>
        /// <returns>A sent email row descriptor.</returns>
        public static SeedEmailOutboxAdminRow Sent(string toAddress)
        {
            return new SeedEmailOutboxAdminRow(toAddress, "Subject", "Body", null, nameof(EmailMessageSensitivity.Normal), nameof(EmailOutboxBodyProtection.None), AdminNow, AdminNow, AdminNow, null, null, null, null, 1, null);
        }

        /// <summary>Creates a retryable row for provider-state assertions.</summary>
        /// <param name="toAddress">Recipient stored with the seeded email.</param>
        /// <returns>A retryable email row descriptor.</returns>
        public static SeedEmailOutboxAdminRow Retryable(string toAddress)
        {
            return new SeedEmailOutboxAdminRow(toAddress, "Subject", "Body", null, nameof(EmailMessageSensitivity.Normal), nameof(EmailOutboxBodyProtection.None), AdminNow, AdminNow, null, null, null, null, null, 1, null);
        }

        /// <summary>Creates a discarded row for provider-state assertions.</summary>
        /// <param name="toAddress">Recipient stored with the seeded email.</param>
        /// <returns>A discarded email row descriptor.</returns>
        public static SeedEmailOutboxAdminRow Discarded(string toAddress)
        {
            return new SeedEmailOutboxAdminRow(toAddress, "Subject", "Body", null, nameof(EmailMessageSensitivity.Normal), nameof(EmailOutboxBodyProtection.None), AdminNow, AdminNow, null, AdminNow.AddMinutes(-1), AdminNow, null, null, 3, "discarded");
        }
    }

    /// <summary>Provider state read back for email outbox admin row state assertions.</summary>
    /// <param name="AvailableAt">Time the email becomes eligible for dispatch.</param>
    /// <param name="FailedAt">Terminal failure time, if failed.</param>
    /// <param name="DiscardedAt">Time further delivery was abandoned, if discarded.</param>
    /// <param name="LockedBy">Worker holding the dispatch lock, if locked.</param>
    /// <param name="LockedUntil">Time the dispatch lock expires, if locked.</param>
    /// <param name="LastError">Safe delivery failure detail, if present.</param>
    protected sealed record EmailOutboxAdminRowState(
        DateTimeOffset AvailableAt,
        DateTimeOffset? FailedAt,
        DateTimeOffset? DiscardedAt,
        string? LockedBy,
        DateTimeOffset? LockedUntil,
        string? LastError);
}
