using Ashlar.Auditing;
using Ashlar.Messaging;

namespace Ashlar.Tests.Messaging;

internal sealed class EmailOutboxAdministrationProviderTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 14, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void SearchRequestDefaultsUseBoundedPaging()
    {
        var request = new EmailOutboxSearchRequest();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Limit, Is.EqualTo(EmailOutboxSearchRequest.DefaultLimit));
            Assert.That(EmailOutboxSearchRequest.MaximumLimit, Is.EqualTo(100));
            Assert.That(EmailOutboxAdministrationProvider.GetStatuses(request), Is.EquivalentTo(Enum.GetValues<EmailOutboxStatus>()));
        }
    }

    [Test]
    public void ValidateSearchRequestRejectsInvalidPagingAndStatuses()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(null!));
            Assert.Throws<ArgumentOutOfRangeException>(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(new EmailOutboxSearchRequest { Limit = 0 }));
            Assert.Throws<ArgumentOutOfRangeException>(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(new EmailOutboxSearchRequest { Limit = 101 }));
            Assert.Throws<ArgumentOutOfRangeException>(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(new EmailOutboxSearchRequest { Offset = -1 }));
            Assert.Throws<ArgumentOutOfRangeException>(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(new EmailOutboxSearchRequest
            {
                Statuses = new HashSet<EmailOutboxStatus> { (EmailOutboxStatus)99 }
            }));
            Assert.DoesNotThrow(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(new EmailOutboxSearchRequest()));
        }
    }

    [Test]
    public void GetStatusesUsesExplicitFilterWhenPresent()
    {
        var statuses = new HashSet<EmailOutboxStatus> { EmailOutboxStatus.Failed };
        var result = EmailOutboxAdministrationProvider.GetStatuses(new EmailOutboxSearchRequest { Statuses = statuses });

        Assert.That(result, Is.SameAs(statuses));
    }

    [Test]
    public void GetStatusesUsesDefaultWhenExplicitFilterIsEmpty()
    {
        var result = EmailOutboxAdministrationProvider.GetStatuses(new EmailOutboxSearchRequest
        {
            Statuses = new HashSet<EmailOutboxStatus>()
        });

        Assert.That(result, Is.SameAs(EmailOutboxAdministrationProvider.DefaultStatuses));
    }

    [Test]
    public void ValidateOperationRequestRequiresIdAndAuditContext()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => EmailOutboxAdministrationProvider.ValidateOperationRequest(null!));
            Assert.Throws<ArgumentException>(() => EmailOutboxAdministrationProvider.ValidateOperationRequest(new EmailOutboxOperationRequest(Guid.Empty, new AuditContext())));
            Assert.Throws<ArgumentNullException>(() => EmailOutboxAdministrationProvider.ValidateOperationRequest(new EmailOutboxOperationRequest(Guid.NewGuid(), null!)));
        }
    }

    [Test]
    public void SafeProjectionSuppressesSensitiveAddressSubjectBodiesAndFailureDetails()
    {
        var record = CreateRecord(
            sensitivity: EmailMessageSensitivity.ContainsLiveSecret,
            bodyProtection: EmailOutboxBodyProtection.SecretProtector,
            lastError: "SMTP failure leaked live-token");

        var summary = EmailOutboxAdministrationProvider.CreateSummary(record);
        var detail = EmailOutboxAdministrationProvider.CreateDetail(record);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summary.ToAddress, Is.Null);
            Assert.That(summary.Subject, Is.Null);
            Assert.That(summary.LastErrorSummary, Is.EqualTo(EmailOutboxAdministrationProvider.SensitiveFailureSummary));
            Assert.That(detail.ToAddress, Is.Null);
            Assert.That(detail.FromAddress, Is.Null);
            Assert.That(detail.ReplyToAddress, Is.Null);
            Assert.That(detail.CcAddress, Is.Null);
            Assert.That(detail.Subject, Is.Null);
            Assert.That(detail.HasTextBody, Is.True);
            Assert.That(detail.HasHtmlBody, Is.True);
            Assert.That(detail.LastErrorSummary, Does.Not.Contain("live-token"));
        }
    }

    [Test]
    public void SafeProjectionDoesNotExposeSensitiveOutboxFields()
    {
        var summaryProperties = typeof(EmailOutboxSummary).GetProperties().Select(property => property.Name).ToArray();
        var detailProperties = typeof(EmailOutboxDetail).GetProperties().Select(property => property.Name).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(summaryProperties, Does.Not.Contain("TextBody"));
            Assert.That(summaryProperties, Does.Not.Contain("HtmlBody"));
            Assert.That(summaryProperties, Does.Not.Contain("Headers"));
            Assert.That(summaryProperties, Does.Not.Contain("Metadata"));
            Assert.That(summaryProperties, Does.Not.Contain("BccAddress"));
            Assert.That(summaryProperties, Does.Not.Contain("LockedBy"));
            Assert.That(detailProperties, Does.Not.Contain("TextBody"));
            Assert.That(detailProperties, Does.Not.Contain("HtmlBody"));
            Assert.That(detailProperties, Does.Not.Contain("Headers"));
            Assert.That(detailProperties, Does.Not.Contain("Metadata"));
            Assert.That(detailProperties, Does.Not.Contain("BccAddress"));
            Assert.That(detailProperties, Does.Not.Contain("LockedBy"));
        }
    }

    [Test]
    public void LastErrorSummaryIsNullSafeSingleLineAndTruncated()
    {
        var longError = "prefix\r\n" + new string('x', EmailOutboxAdministrationProvider.MaxLastErrorSummaryLength + 10);
        var summary = EmailOutboxAdministrationProvider.CreateLastErrorSummary(CreateRecord(lastError: longError));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(EmailOutboxAdministrationProvider.CreateLastErrorSummary(CreateRecord(lastError: "short failure")), Is.EqualTo("short failure"));
            Assert.That(EmailOutboxAdministrationProvider.CreateLastErrorSummary(CreateRecord(lastError: null)), Is.Null);
            Assert.That(summary, Has.Length.EqualTo(EmailOutboxAdministrationProvider.MaxLastErrorSummaryLength));
            Assert.That(summary, Does.Not.Contain("\r"));
            Assert.That(summary, Does.Not.Contain("\n"));
        }
    }

    [Test]
    public void ParseStatusHandlesMalformedProviderValues()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(EmailOutboxAdministrationProvider.ParseStatus(nameof(EmailOutboxStatus.Failed)), Is.EqualTo(EmailOutboxStatus.Failed));
            Assert.That(EmailOutboxAdministrationProvider.ParseStatus(null), Is.EqualTo(EmailOutboxStatus.Pending));
            Assert.That(EmailOutboxAdministrationProvider.ParseStatus("unknown"), Is.EqualTo(EmailOutboxStatus.Pending));
            Assert.That(EmailOutboxAdministrationProvider.ParseStatus("99"), Is.EqualTo(EmailOutboxStatus.Pending));
        }
    }

    [Test]
    public void CreateOperationResultSanitizesPublicFields()
    {
        var state = new EmailOutboxAdministrationOperationState(Guid.NewGuid(), "state@example.com", "State subject", EmailOutboxStatus.Pending);
        var safe = EmailOutboxAdministrationProvider.CreateOperationResult(
            EmailOutboxOperationStatus.Retried,
            Guid.NewGuid(),
            "user@example.com",
            "Subject",
            EmailOutboxStatus.Pending);
        var unsafeResult = EmailOutboxAdministrationProvider.CreateOperationResult(
            EmailOutboxOperationStatus.Discarded,
            Guid.NewGuid(),
            "bad\nrecipient@example.com",
            "bad\rsubject",
            EmailOutboxStatus.Discarded);
        var suppressed = EmailOutboxAdministrationProvider.CreateOperationResult(
            EmailOutboxOperationStatus.Retried,
            Guid.NewGuid(),
            "secret@example.com",
            "Token",
            EmailOutboxStatus.Pending,
            suppressPublicFields: true);
        var fromState = EmailOutboxAdministrationProvider.CreateOperationResult(EmailOutboxOperationStatus.Retried, state);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(safe.ToAddress, Is.EqualTo("user@example.com"));
            Assert.That(safe.Subject, Is.EqualTo("Subject"));
            Assert.That(safe.OutboxStatus, Is.EqualTo(EmailOutboxStatus.Pending));
            Assert.That(unsafeResult.ToAddress, Is.Null);
            Assert.That(unsafeResult.Subject, Is.Null);
            Assert.That(suppressed.ToAddress, Is.Null);
            Assert.That(suppressed.Subject, Is.Null);
            Assert.That(fromState.ToAddress, Is.EqualTo("state@example.com"));
            Assert.That(Assert.Throws<ArgumentNullException>(() => EmailOutboxAdministrationProvider.CreateOperationResult(EmailOutboxOperationStatus.Retried, null!))?.ParamName, Is.EqualTo("state"));
        }
    }

    [Test]
    public void CreateNoOpResultReturnsStableStatuses()
    {
        var id = Guid.NewGuid();
        var pending = new EmailOutboxAdministrationOperationState(id, "user@example.com", "Subject", EmailOutboxStatus.Pending);
        var discarded = new EmailOutboxAdministrationOperationState(id, "user@example.com", "Subject", EmailOutboxStatus.Discarded);

        var missingResult = EmailOutboxAdministrationProvider.CreateNoOpResult(id, null);
        var pendingResult = EmailOutboxAdministrationProvider.CreateNoOpResult(id, pending);
        var discardedResult = EmailOutboxAdministrationProvider.CreateNoOpResult(id, discarded);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingResult.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFound));
            Assert.That(pendingResult.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFailed));
            Assert.That(pendingResult.OutboxStatus, Is.EqualTo(EmailOutboxStatus.Pending));
            Assert.That(discardedResult.Status, Is.EqualTo(EmailOutboxOperationStatus.AlreadyDiscarded));
            Assert.That(discardedResult.OutboxStatus, Is.EqualTo(EmailOutboxStatus.Discarded));
        }
    }

    [Test]
    public async Task RecordSuccessfulOperationAsyncRecordsAuditAndValidatesInputs()
    {
        var sink = new CapturingSecurityEventSink();
        var id = Guid.NewGuid();
        var actorUserId = Guid.NewGuid();
        var request = new EmailOutboxOperationRequest(id, new AuditContext
        {
            ActorUserId = actorUserId,
            IpAddress = "127.0.0.1",
            UserAgent = "tests",
            CorrelationId = "correlation"
        });
        var result = EmailOutboxAdministrationProvider.CreateOperationResult(EmailOutboxOperationStatus.Retried, id);

        await EmailOutboxAdministrationProvider.RecordSuccessfulOperationAsync(
            sink,
            TimeProvider.System,
            AshlarSecurityEventTypes.EmailOutboxDeliveryRetried,
            request,
            result,
            CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sink.Events, Has.Count.EqualTo(1));
            Assert.That(sink.Events[0].EventType, Is.EqualTo(AshlarSecurityEventTypes.EmailOutboxDeliveryRetried));
            Assert.That(sink.Events[0].ActorUserId, Is.EqualTo(actorUserId));
            Assert.That(sink.Events[0].Properties, Contains.Key("email_outbox_id"));
            Assert.That(sink.Events[0].Properties?["email_outbox_id"], Is.EqualTo(id.ToString("D")));
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxAdministrationProvider.RecordSuccessfulOperationAsync(null!, TimeProvider.System, "event", request, result, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxAdministrationProvider.RecordSuccessfulOperationAsync(sink, null!, "event", request, result, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentException>(() => EmailOutboxAdministrationProvider.RecordSuccessfulOperationAsync(sink, TimeProvider.System, "", request, result, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxAdministrationProvider.RecordSuccessfulOperationAsync(sink, TimeProvider.System, "event", null!, result, CancellationToken.None));
            Assert.ThrowsAsync<ArgumentNullException>(() => EmailOutboxAdministrationProvider.RecordSuccessfulOperationAsync(sink, TimeProvider.System, "event", request, null!, CancellationToken.None));
        }
    }

    private static EmailOutboxAdministrationProjection CreateRecord(
        EmailMessageSensitivity sensitivity = EmailMessageSensitivity.Normal,
        EmailOutboxBodyProtection bodyProtection = EmailOutboxBodyProtection.None,
        string? lastError = "failure")
    {
        return new EmailOutboxAdministrationProjection(
            Guid.NewGuid(),
            "to@example.com",
            "from@example.com",
            "reply@example.com",
            "cc@example.com",
            "bcc@example.com",
            "Subject",
            "Text live-token",
            "<p>Html live-token</p>",
            """{"Authorization":"Bearer secret"}""",
            """{"Trace":"secret"}""",
            sensitivity,
            bodyProtection,
            EmailOutboxStatus.Failed,
            3,
            Now.AddMinutes(-10),
            Now,
            Now.AddMinutes(-1),
            Now,
            null,
            null,
            "worker",
            Now.AddMinutes(1),
            lastError);
    }

    private sealed class CapturingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }
}
