using Ashlar.Auditing;
using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.Testing;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Messaging;

internal sealed class EmailOutboxAdministrationProviderTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 14, 12, 0, 0, TimeSpan.Zero);
    private static readonly AccountSecurityActorTestContext Security =
        new(Now, IAccountSecurityAdministrationService.ProofPurpose);

    [Test]
    public void SearchRequestDefaultsUseBoundedPaging()
    {
        var request = new EmailOutboxSearchRequest
        {
            Scope = OperationalAdministrationScope.Unspecified
        };

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
            Assert.Throws<ArgumentOutOfRangeException>(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(ValidSearch() with { Limit = 0 }));
            Assert.Throws<ArgumentOutOfRangeException>(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(ValidSearch() with { Limit = 101 }));
            Assert.Throws<ArgumentOutOfRangeException>(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(ValidSearch() with { Offset = -1 }));
            Assert.Throws<ArgumentOutOfRangeException>(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(new EmailOutboxSearchRequest
            {
                Actor = Security.Actor,
                Scope = OperationalAdministrationScope.Global,
                Statuses = new HashSet<EmailOutboxStatus> { (EmailOutboxStatus)99 }
            }));
            Assert.DoesNotThrow(() => EmailOutboxAdministrationProvider.ValidateSearchRequest(ValidSearch()));
        }
    }

    [Test]
    public void GetStatusesUsesExplicitFilterWhenPresent()
    {
        var statuses = new HashSet<EmailOutboxStatus> { EmailOutboxStatus.Failed };
        var result = EmailOutboxAdministrationProvider.GetStatuses(new EmailOutboxSearchRequest
        {
            Scope = OperationalAdministrationScope.Global,
            Statuses = statuses
        });

        Assert.That(result, Is.SameAs(statuses));
    }

    [Test]
    public void GetStatusesUsesDefaultWhenExplicitFilterIsEmpty()
    {
        var result = EmailOutboxAdministrationProvider.GetStatuses(new EmailOutboxSearchRequest
        {
            Scope = OperationalAdministrationScope.Global,
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
            Assert.Throws<ArgumentException>(() => EmailOutboxAdministrationProvider.ValidateOperationRequest(new EmailOutboxOperationRequest(Guid.Empty, Security.Actor, OperationalAdministrationScope.Global)));
            Assert.Throws<ArgumentNullException>(() => EmailOutboxAdministrationProvider.ValidateOperationRequest(new EmailOutboxOperationRequest(Guid.NewGuid(), null!, OperationalAdministrationScope.Global)));
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
        var providerProperties = typeof(EmailOutboxAdministrationProjection).GetProperties().Select(property => property.Name);

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
            Assert.That(providerProperties.Intersect(
                ["TextBody", "HtmlBody", "Headers", "Metadata", "BccAddress", "LockedBy", "LockedUntil", "LastError"]), Is.Empty);
        }
    }

    [Test]
    public void LastErrorSummaryIsNullSafeSingleLineAndTruncated()
    {
        var longError = "prefix\r\n" + new string('x', EmailOutboxAdministrationProvider.MaxLastErrorSummaryLength + 10);
        var summary = EmailOutboxAdministrationProvider.CreateLastErrorSummary(CreateRecord(lastError: longError));
        var injectedSensitive = CreateRecord() with
        {
            Sensitivity = EmailMessageSensitivity.ContainsLiveSecret,
            LastErrorSummary = "injected live-token"
        };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(EmailOutboxAdministrationProvider.CreateLastErrorSummary(CreateRecord(lastError: "short failure")), Is.EqualTo("short failure"));
            Assert.That(EmailOutboxAdministrationProvider.CreateLastErrorSummary(CreateRecord(lastError: null)), Is.Null);
            Assert.That(summary, Has.Length.EqualTo(EmailOutboxAdministrationProvider.MaxLastErrorSummaryLength));
            Assert.That(summary, Does.Not.Contain("\r"));
            Assert.That(summary, Does.Not.Contain("\n"));
            Assert.That(EmailOutboxAdministrationProvider.CreateLastErrorSummary(injectedSensitive),
                Is.EqualTo(EmailOutboxAdministrationProvider.SensitiveFailureSummary));
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
        var state = new EmailOutboxAdministrationOperationState(
            Guid.NewGuid(), "state@example.com", "State subject", EmailOutboxStatus.Pending,
            EmailMessageSensitivity.Normal, EmailOutboxBodyProtection.None);
        var sensitiveState = state with { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret };
        var safe = EmailOutboxAdministrationProvider.CreateOperationResult(
            EmailOutboxOperationStatus.Retried,
            Guid.NewGuid(),
            suppressPublicFields: false,
            "user@example.com",
            "Subject",
            EmailOutboxStatus.Pending);
        var unsafeResult = EmailOutboxAdministrationProvider.CreateOperationResult(
            EmailOutboxOperationStatus.Discarded,
            Guid.NewGuid(),
            suppressPublicFields: false,
            "bad\nrecipient@example.com",
            "bad\rsubject",
            EmailOutboxStatus.Discarded);
        var suppressed = EmailOutboxAdministrationProvider.CreateOperationResult(
            EmailOutboxOperationStatus.Retried,
            Guid.NewGuid(),
            suppressPublicFields: true,
            "secret@example.com",
            "Token",
            EmailOutboxStatus.Pending);
        var fromState = EmailOutboxAdministrationProvider.CreateOperationResult(EmailOutboxOperationStatus.Retried, state);
        var fromSensitiveState = EmailOutboxAdministrationProvider.CreateOperationResult(
            EmailOutboxOperationStatus.Retried, sensitiveState);

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
            Assert.That(fromSensitiveState.ToAddress, Is.Null);
            Assert.That(Assert.Throws<ArgumentNullException>(() => EmailOutboxAdministrationProvider.CreateOperationResult(EmailOutboxOperationStatus.Retried, null!))?.ParamName, Is.EqualTo("state"));
        }
    }

    [Test]
    public void CreateNoOpResultReturnsStableStatuses()
    {
        var id = Guid.NewGuid();
        var pending = new EmailOutboxAdministrationOperationState(
            id, "user@example.com", "Subject", EmailOutboxStatus.Pending,
            EmailMessageSensitivity.Normal, EmailOutboxBodyProtection.None);
        var discarded = pending with { Status = EmailOutboxStatus.Discarded };
        var sensitive = pending with { Sensitivity = EmailMessageSensitivity.ContainsLiveSecret };

        var missingResult = EmailOutboxAdministrationProvider.CreateNoOpResult(id, null);
        var pendingResult = EmailOutboxAdministrationProvider.CreateNoOpResult(id, pending);
        var discardedResult = EmailOutboxAdministrationProvider.CreateNoOpResult(id, discarded);
        var sensitiveResult = EmailOutboxAdministrationProvider.CreateNoOpResult(id, sensitive);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingResult.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFound));
            Assert.That(pendingResult.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFailed));
            Assert.That(pendingResult.OutboxStatus, Is.EqualTo(EmailOutboxStatus.Pending));
            Assert.That(discardedResult.Status, Is.EqualTo(EmailOutboxOperationStatus.AlreadyDiscarded));
            Assert.That(discardedResult.OutboxStatus, Is.EqualTo(EmailOutboxStatus.Discarded));
            Assert.That(sensitiveResult.ToAddress, Is.Null);
        }
    }

    [Test]
    public async Task RecordSuccessfulOperationAsyncRecordsAuditAndValidatesInputs()
    {
        var sink = new CapturingSecurityEventSink();
        var id = Guid.NewGuid();
        var actorUserId = Guid.NewGuid();
        var actor = CreateActor(actorUserId, new AuditContext(actorUserId, "127.0.0.1", "tests", "correlation"));
        var request = new EmailOutboxOperationRequest(id, actor, OperationalAdministrationScope.Global);
        var result = EmailOutboxAdministrationProvider.CreateOperationResult(EmailOutboxOperationStatus.Retried, id, suppressPublicFields: true);

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

    [Test]
    public void ServiceBaseRequiresAuditAndTransactionDependencies()
    {
        var sink = new CapturingSecurityEventSink();
        Assert.Throws<ArgumentNullException>(() => new TestEmailOutboxAdministrationService(null!, new Support.RecordingTransactionProvider()));
        Assert.Throws<ArgumentNullException>(() => new TestEmailOutboxAdministrationService(sink, null!));
    }

    [Test]
    public async Task ServiceBaseCommitsOperationWithTransactionProvider()
    {
        var sink = new CapturingSecurityEventSink();
        var transactionProvider = new Support.RecordingTransactionProvider();
        var service = new TestEmailOutboxAdministrationService(sink, transactionProvider);

        var result = await service.RetryAsync(new EmailOutboxOperationRequest(Guid.NewGuid(), Security.Actor, OperationalAdministrationScope.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(EmailOutboxOperationStatus.Retried));
            Assert.That(transactionProvider.Transaction.CommitCount, Is.EqualTo(1));
            Assert.That(transactionProvider.Transaction.DisposeCount, Is.EqualTo(1));
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
            "Subject",
            true,
            true,
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
            EmailOutboxAdministrationProvider.CreateLastErrorSummary(lastError, sensitivity, bodyProtection));
    }

    [Test]
    public async Task PublicBoundaryRejectsInvalidOrUnauthorizedActorsBeforeProviderWork()
    {
        var unauthorized = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose, authorized: false);
        var transactions = new Support.RecordingTransactionProvider();
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), transactions, unauthorized);

        var search = await service.SearchAsync(new() { Actor = unauthorized.Actor, Scope = OperationalAdministrationScope.Global });
        var retry = await service.RetryAsync(new(Guid.NewGuid(), unauthorized.Actor, OperationalAdministrationScope.Global));

        Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.SearchAsync(new() { Scope = OperationalAdministrationScope.Global }));
        Assert.ThrowsAsync<ArgumentException>(() =>
            service.SearchAsync(new() { Actor = unauthorized.Actor, Scope = OperationalAdministrationScope.Unspecified }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(search.Items, Is.Empty);
            Assert.That(retry.Status, Is.EqualTo(EmailOutboxOperationStatus.Failed));
            Assert.That(service.ProviderCalls, Is.Zero);
            Assert.That(transactions.Transaction.BeginCount, Is.Zero);
        }
    }

    [TestCase("id")]
    [TestCase("status")]
    [TestCase("sensitivity")]
    [TestCase("protection")]
    [TestCase("attempts")]
    public void SafeProjectionRejectsMalformedProviderValues(string field)
    {
        var record = field switch
        {
            "id" => CreateRecord() with { Id = Guid.Empty },
            "status" => CreateRecord() with { Status = (EmailOutboxStatus)99 },
            "sensitivity" => CreateRecord() with { Sensitivity = (EmailMessageSensitivity)99 },
            "protection" => CreateRecord() with { BodyProtection = (EmailOutboxBodyProtection)99 },
            _ => CreateRecord() with { AttemptCount = -1 }
        };

        Assert.Throws<InvalidOperationException>(() => EmailOutboxAdministrationProvider.CreateSummary(record));
    }

    [TestCase(false)]
    [TestCase(true)]
    public void ServiceBaseRejectsMismatchedMutationState(bool afterNoOp)
    {
        var sink = new CapturingSecurityEventSink();
        var transactionProvider = new Support.RecordingTransactionProvider();
        var service = new TestEmailOutboxAdministrationService(sink, transactionProvider)
        {
            ReturnNoMutationState = afterNoOp,
            ReturnMismatchedMutationState = !afterNoOp,
            ReturnMismatchedLoadState = afterNoOp
        };

        Assert.ThrowsAsync<InvalidOperationException>(() => service.RetryAsync(new(
            Guid.NewGuid(), Security.Actor, OperationalAdministrationScope.Global)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sink.Events, Is.Empty);
            Assert.That(transactionProvider.Transaction.CommitCount, Is.Zero);
        }
    }

    [Test]
    public async Task ServiceBaseAcceptsMatchingNoOpState()
    {
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider())
        {
            ReturnNoMutationState = true
        };

        var result = await service.RetryAsync(new(
            Guid.NewGuid(), Security.Actor, OperationalAdministrationScope.Global));

        Assert.That(result.Status, Is.EqualTo(EmailOutboxOperationStatus.NotFailed));
    }

    [Test]
    public void ServiceBaseRejectsInvalidMutationPostState()
    {
        var sink = new CapturingSecurityEventSink();
        var transactionProvider = new Support.RecordingTransactionProvider();
        var service = new TestEmailOutboxAdministrationService(sink, transactionProvider)
        {
            ReturnInvalidMutationPostState = true
        };

        Assert.ThrowsAsync<InvalidOperationException>(() => service.RetryAsync(new(
            Guid.NewGuid(), Security.Actor, OperationalAdministrationScope.Global)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sink.Events, Is.Empty);
            Assert.That(transactionProvider.Transaction.CommitCount, Is.Zero);
        }
    }

    [TestCase("status")]
    [TestCase("sensitivity")]
    [TestCase("protection")]
    public void ServiceBaseRejectsInvalidMutationProviderState(string field)
    {
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider())
        {
            InvalidMutationStateField = field
        };

        Assert.ThrowsAsync<InvalidOperationException>(() => service.RetryAsync(new(
            Guid.NewGuid(), Security.Actor, OperationalAdministrationScope.Global)));
    }

    [TestCase(EmailOutboxStatus.Failed)]
    [TestCase((EmailOutboxStatus)99)]
    public void ServiceBaseRejectsInvalidNoOpState(EmailOutboxStatus status)
    {
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider())
        {
            ReturnNoMutationState = true,
            LoadStateStatus = status
        };

        Assert.ThrowsAsync<InvalidOperationException>(() => service.RetryAsync(new(
            Guid.NewGuid(), Security.Actor, OperationalAdministrationScope.Global)));
    }

    [Test]
    public async Task MutationRejectsAdministrationReadProof()
    {
        var readSecurity = new AccountSecurityActorTestContext(
            Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), readSecurity);

        var result = await service.RetryAsync(new(
            Guid.NewGuid(), readSecurity.Actor, OperationalAdministrationScope.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(EmailOutboxOperationStatus.Failed));
            Assert.That(service.ProviderCalls, Is.Zero);
        }
    }

    [Test]
    public async Task SearchAndDetailRecordDurableReadAudit()
    {
        var security = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), security);

        await service.SearchAsync(new() { Actor = security.Actor, Scope = OperationalAdministrationScope.Global });
        await service.GetAsync(new(Guid.NewGuid(), security.Actor, OperationalAdministrationScope.Global));

        Assert.That(security.AuditSink.Events.Select(static e => e.Outcome),
            Is.EqualTo(new[] { SecurityEventOutcomes.Success, SecurityEventOutcomes.Success }));
    }

    [Test]
    public async Task ReadBoundaryAuditsProviderFailuresAndMissingDetail()
    {
        var security = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), security)
        {
            ThrowSearch = true
        };

        Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.SearchAsync(new() { Actor = security.Actor, Scope = OperationalAdministrationScope.Global }));
        service.ThrowSearch = false;
        service.ReturnNullDetail = true;
        Assert.That(await service.GetAsync(new(Guid.NewGuid(), security.Actor, OperationalAdministrationScope.Global)), Is.Null);
        service.ReturnNullDetail = false;
        service.ReturnMismatchedDetail = true;
        Assert.That(await service.GetAsync(new(Guid.NewGuid(), security.Actor, OperationalAdministrationScope.Global)), Is.Null);
        service.ReturnMismatchedDetail = false;
        service.ReturnInvalidDetailProjection = true;
        Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.GetAsync(new(Guid.NewGuid(), security.Actor, OperationalAdministrationScope.Global)));
        service.ReturnInvalidDetailProjection = false;
        service.ThrowDetail = true;
        Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.GetAsync(new(Guid.NewGuid(), security.Actor, OperationalAdministrationScope.Global)));

        Assert.That(security.AuditSink.Events.Select(static e => e.Outcome),
            Is.All.EqualTo(SecurityEventOutcomes.Failure));
    }

    [Test]
    public void ReadBoundaryAuditsValidatedRequestFailures()
    {
        var security = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), security);

        Assert.ThrowsAsync<ArgumentNullException>(() => service.SearchAsync(null!));
        Assert.ThrowsAsync<ArgumentNullException>(() => service.GetAsync(null!));
        Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => service.SearchAsync(new()
        {
            Actor = security.Actor,
            Scope = OperationalAdministrationScope.Global,
            Limit = 0
        }));
        Assert.ThrowsAsync<ArgumentException>(() => service.GetAsync(new(
            Guid.Empty, security.Actor, OperationalAdministrationScope.Global)));

        Assert.That(security.AuditSink.Events.Select(static e => e.Outcome),
            Is.All.EqualTo(SecurityEventOutcomes.Failure));
    }

    [Test]
    public void ReadAuditFailureIsNotRetriedAsAProviderFailure()
    {
        var security = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var audit = new ThrowingPersistentSecurityEventSink();
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), security, audit);

        Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.SearchAsync(new() { Actor = security.Actor, Scope = OperationalAdministrationScope.Global }));

        Assert.That(audit.CallCount, Is.EqualTo(1));
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    public void SearchRejectsMalformedProviderPageBeforeSuccessAudit(int malformedPage)
    {
        var security = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), security)
        {
            ReturnInvalidSearch = true,
            ReturnNullSearchItem = malformedPage == 1,
            ReturnDuplicateSearchEntries = malformedPage == 2,
            ReturnOutOfFilterSearchEntry = malformedPage == 3
        };

        Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.SearchAsync(new()
            {
                Actor = security.Actor,
                Scope = OperationalAdministrationScope.Global,
                Statuses = malformedPage == 3 ? new HashSet<EmailOutboxStatus> { EmailOutboxStatus.Pending } : null
            }));

        Assert.That(security.AuditSink.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
    }

    [Test]
    public async Task DetailRejectsUnauthorizedActorBeforeProviderWork()
    {
        var security = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose, authorized: false);
        var service = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), security);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await service.GetAsync(new(Guid.NewGuid(), security.Actor, OperationalAdministrationScope.Global)), Is.Null);
            Assert.That(service.ProviderCalls, Is.Zero);
        }
    }

    [Test]
    public async Task PublicBoundaryRejectsInactiveOrRevokedSessionsAndAuditActorMismatch()
    {
        var revoked = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
        revoked.Sessions.Session!.RevokedAt = Now;
        var revokedService = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), revoked);
        var inactive = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
        inactive.Sessions.Session = null;
        var inactiveService = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), inactive);
        var mismatch = new AccountSecurityActorTestContext(Now, AccountSecurityActorContext.AdministrationReadProofPurpose);
        mismatch.Actor = new(mismatch.Actor.ActorUserId, mismatch.Actor.ActorTenant,
            mismatch.Actor.CurrentSessionId, mismatch.Actor.FreshMfaProof, new AuditContext(Guid.NewGuid()));
        var mismatchService = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), new Support.RecordingTransactionProvider(), mismatch);
        var revokedMutation = new AccountSecurityActorTestContext(
            Now, IAccountSecurityAdministrationService.ProofPurpose);
        revokedMutation.Sessions.Session!.RevokedAt = Now;
        var revokedMutationTransactions = new Support.RecordingTransactionProvider();
        var revokedMutationService = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), revokedMutationTransactions, revokedMutation);
        var mismatchMutation = new AccountSecurityActorTestContext(
            Now, IAccountSecurityAdministrationService.ProofPurpose);
        mismatchMutation.Actor = new(mismatchMutation.Actor.ActorUserId, mismatchMutation.Actor.ActorTenant,
            mismatchMutation.Actor.CurrentSessionId, mismatchMutation.Actor.FreshMfaProof, new AuditContext(Guid.NewGuid()));
        var mismatchMutationTransactions = new Support.RecordingTransactionProvider();
        var mismatchMutationService = new TestEmailOutboxAdministrationService(
            new CapturingSecurityEventSink(), mismatchMutationTransactions, mismatchMutation);

        var revokedResult = await revokedService.SearchAsync(new() { Actor = revoked.Actor, Scope = OperationalAdministrationScope.Global });
        var inactiveResult = await inactiveService.GetAsync(new(Guid.NewGuid(), inactive.Actor, OperationalAdministrationScope.Global));
        var mismatchResult = await mismatchService.SearchAsync(new() { Actor = mismatch.Actor, Scope = OperationalAdministrationScope.Global });
        var revokedMutationResult = await revokedMutationService.DiscardAsync(new(
            Guid.NewGuid(), revokedMutation.Actor, OperationalAdministrationScope.Global));
        var mismatchMutationResult = await mismatchMutationService.RetryAsync(new(
            Guid.NewGuid(), mismatchMutation.Actor, OperationalAdministrationScope.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revokedResult.Items, Is.Empty);
            Assert.That(inactiveResult, Is.Null);
            Assert.That(mismatchResult.Items, Is.Empty);
            Assert.That(revokedMutationResult.Status, Is.EqualTo(EmailOutboxOperationStatus.Failed));
            Assert.That(mismatchMutationResult.Status, Is.EqualTo(EmailOutboxOperationStatus.Failed));
            Assert.That(revokedService.ProviderCalls, Is.Zero);
            Assert.That(inactiveService.ProviderCalls, Is.Zero);
            Assert.That(mismatchService.ProviderCalls, Is.Zero);
            Assert.That(revokedMutationService.ProviderCalls, Is.Zero);
            Assert.That(mismatchMutationService.ProviderCalls, Is.Zero);
            Assert.That(revokedMutationTransactions.Transaction.BeginCount, Is.Zero);
            Assert.That(mismatchMutationTransactions.Transaction.BeginCount, Is.Zero);
        }
    }

    private static EmailOutboxSearchRequest ValidSearch() =>
        new() { Actor = Security.Actor, Scope = OperationalAdministrationScope.Global };

    private static AccountSecurityActorContext CreateActor(Guid userId, AuditContext audit) =>
        new(userId, TenantContext.Global, Security.Actor.CurrentSessionId,
            FreshMfaVerificationProofFactory.Create(userId, null, Security.Actor.CurrentSessionId, Now,
                Now.AddMinutes(5), AccountSecurityActorContext.AdministrationReadProofPurpose), audit);

    private sealed class CapturingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingPersistentSecurityEventSink : IPersistentSecurityEventSink
    {
        public int CallCount { get; private set; }

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            CallCount++;
            throw new InvalidOperationException("audit failed");
        }
    }

    private sealed class TestEmailOutboxAdministrationService(
        ISecurityEventSink sink,
        global::Ashlar.Identity.Abstractions.Transactions.IAshlarTransactionProvider transactionProvider,
        AccountSecurityActorTestContext? security = null,
        IPersistentSecurityEventSink? auditSink = null)
        : EmailOutboxAdministrationServiceBase(
            new FakeTimeProvider(Now),
            sink,
            global::Ashlar.Testing.DurableTransactionComposition.Create(transactionProvider),
            CreateAdministrationContext(security ?? Security, auditSink))
    {
        public int ProviderCalls { get; private set; }
        public bool ThrowSearch { get; set; }
        public bool ThrowDetail { get; set; }
        public bool ReturnNullDetail { get; set; }
        public bool ReturnMismatchedDetail { get; set; }
        public bool ReturnInvalidDetailProjection { get; set; }
        public bool ReturnInvalidSearch { get; set; }
        public bool ReturnNullSearchItem { get; set; }
        public bool ReturnDuplicateSearchEntries { get; set; }
        public bool ReturnOutOfFilterSearchEntry { get; set; }
        public bool ReturnMismatchedMutationState { get; set; }
        public bool ReturnInvalidMutationPostState { get; set; }
        public string? InvalidMutationStateField { get; set; }
        public bool ReturnNoMutationState { get; set; }
        public bool ReturnMismatchedLoadState { get; set; }

        private static AshlarOperationalAdministrationContext CreateAdministrationContext(
            AccountSecurityActorTestContext security,
            IPersistentSecurityEventSink? auditSink)
        {
            var sink = auditSink ?? security.AuditSink;
            var timeProvider = new FakeTimeProvider(Now);
            return new(
                new(security.Sessions, security.Authorizer, sink, timeProvider, eventType: "email_outbox.administration"),
                new(security.Sessions, security.Authorizer, sink, timeProvider,
                    IAccountSecurityAdministrationService.ProofPurpose, "email_outbox.administration"));
        }
        public EmailOutboxStatus LoadStateStatus { get; set; } = EmailOutboxStatus.Pending;

        protected override Task<EmailOutboxAdministrationProviderSearchResult> SearchAuthorizedAsync(
            EmailOutboxSearchRequest request, CancellationToken cancellationToken)
        {
            ProviderCalls++;
            if (ThrowSearch) throw new InvalidOperationException("search failed");
            List<EmailOutboxAdministrationProjection> items = ReturnInvalidSearch
                ? ReturnNullSearchItem
                    ? [null!]
                    : ReturnDuplicateSearchEntries
                        ? [CreateRecord()]
                        : ReturnOutOfFilterSearchEntry
                            ? [CreateRecord()]
                        : Enumerable.Repeat(CreateRecord(), request.Limit + 1).ToList()
                : [];
            if (ReturnDuplicateSearchEntries)
                items = [items[0], items[0]];
            return Task.FromResult(new EmailOutboxAdministrationProviderSearchResult(items, false));
        }

        protected override Task<EmailOutboxAdministrationProjection?> GetAuthorizedAsync(
            Guid id, CancellationToken cancellationToken)
        {
            ProviderCalls++;
            if (ThrowDetail) throw new InvalidOperationException("detail failed");
            if (ReturnNullDetail) return Task.FromResult<EmailOutboxAdministrationProjection?>(null);
            if (ReturnMismatchedDetail) id = Guid.NewGuid();
            return Task.FromResult<EmailOutboxAdministrationProjection?>(CreateRecord() with
            {
                Id = id,
                AttemptCount = ReturnInvalidDetailProjection ? -1 : 3
            });
        }

        protected override Task<EmailOutboxAdministrationOperationState?> RetryFailedAsync(Guid id, CancellationToken cancellationToken)
        {
            if (ReturnNoMutationState) return Task.FromResult<EmailOutboxAdministrationOperationState?>(null);
            if (ReturnMismatchedMutationState) id = Guid.NewGuid();
            var status = InvalidMutationStateField == "status"
                ? (EmailOutboxStatus)99
                : ReturnInvalidMutationPostState ? EmailOutboxStatus.Sent : EmailOutboxStatus.Pending;
            var sensitivity = InvalidMutationStateField == "sensitivity"
                ? (EmailMessageSensitivity)99
                : EmailMessageSensitivity.Normal;
            var bodyProtection = InvalidMutationStateField == "protection"
                ? (EmailOutboxBodyProtection)99
                : EmailOutboxBodyProtection.None;
            return Task.FromResult<EmailOutboxAdministrationOperationState?>(new(
                id, "retry@example.com", "Retry", status,
                sensitivity, bodyProtection));
        }

        protected override Task<EmailOutboxAdministrationOperationState?> DiscardFailedAsync(Guid id, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        protected override Task<EmailOutboxAdministrationOperationState?> LoadOperationStateAsync(Guid id, CancellationToken cancellationToken)
        {
            if (!ReturnNoMutationState) throw new NotSupportedException();
            if (ReturnMismatchedLoadState) id = Guid.NewGuid();
            return Task.FromResult<EmailOutboxAdministrationOperationState?>(new(
                id, "retry@example.com", "Retry", LoadStateStatus,
                EmailMessageSensitivity.Normal, EmailOutboxBodyProtection.None));
        }
    }
}
