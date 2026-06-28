using System.Net;
using Ashlar.Webhooks.SecurityEvents;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarSecurityEventWebhookOutboxBrowserTests
{
    [Test]
    public void BrowseRequestDefaultsUseBoundedPaging()
    {
        var request = new AshlarSecurityEventWebhookOutboxBrowseRequest();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Limit, Is.EqualTo(AshlarSecurityEventWebhookOutboxBrowseRequest.DefaultLimit));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowseRequest.MaximumLimit, Is.EqualTo(100));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.GetStatuses(request), Is.EquivalentTo(Enum.GetValues<AshlarSecurityEventWebhookOutboxStatus>()));
        }
    }

    [Test]
    public void ValidateRequestRejectsInvalidPagingAndStatuses()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxBrowser.ValidateRequest(null!));
            Assert.Throws<ArgumentOutOfRangeException>(() => AshlarSecurityEventWebhookOutboxBrowser.ValidateRequest(new AshlarSecurityEventWebhookOutboxBrowseRequest { Limit = 0 }));
            Assert.Throws<ArgumentOutOfRangeException>(() => AshlarSecurityEventWebhookOutboxBrowser.ValidateRequest(new AshlarSecurityEventWebhookOutboxBrowseRequest { Limit = 101 }));
            Assert.Throws<ArgumentOutOfRangeException>(() => AshlarSecurityEventWebhookOutboxBrowser.ValidateRequest(new AshlarSecurityEventWebhookOutboxBrowseRequest { Offset = -1 }));
            Assert.Throws<ArgumentOutOfRangeException>(() => AshlarSecurityEventWebhookOutboxBrowser.ValidateRequest(new AshlarSecurityEventWebhookOutboxBrowseRequest
            {
                Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { (AshlarSecurityEventWebhookOutboxStatus)99 }
            }));
        }
    }

    [Test]
    public void ValidateRequestAcceptsExplicitSupportedStatuses()
    {
        Assert.DoesNotThrow(() => AshlarSecurityEventWebhookOutboxBrowser.ValidateRequest(new AshlarSecurityEventWebhookOutboxBrowseRequest
        {
            Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Pending }
        }));
    }

    [Test]
    public void GetStatusesUsesExplicitFilterWhenPresent()
    {
        var statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus> { AshlarSecurityEventWebhookOutboxStatus.Failed };
        var result = AshlarSecurityEventWebhookOutboxBrowser.GetStatuses(new AshlarSecurityEventWebhookOutboxBrowseRequest { Statuses = statuses });

        Assert.That(result, Is.SameAs(statuses));
    }

    [Test]
    public void GetStatusesUsesDefaultWhenExplicitFilterIsEmpty()
    {
        var result = AshlarSecurityEventWebhookOutboxBrowser.GetStatuses(new AshlarSecurityEventWebhookOutboxBrowseRequest
        {
            Statuses = new HashSet<AshlarSecurityEventWebhookOutboxStatus>()
        });

        Assert.That(result, Is.SameAs(AshlarSecurityEventWebhookOutboxBrowser.DefaultStatuses));
    }

    [Test]
    public void SafeTextSanitizationIsDefensive()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText("audit"), Is.EqualTo("audit"));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText(null), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText(" "), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText("bad\nvalue"), Is.Null);
        }
    }

    [Test]
    public void LastErrorSummaryOnlyAllowsSafePersistedFailureDetails()
    {
        var summary = AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=http_status;status=502;reason=non_success_status");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary(null), Is.Null);
            Assert.That(summary, Is.EqualTo("kind=http_status;status=502;reason=non_success_status"));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=timeout;reason=delivery_timeout"), Is.EqualTo("kind=timeout;reason=delivery_timeout"));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=canceled;reason=delivery_canceled"), Is.EqualTo("kind=canceled;reason=delivery_canceled"));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=transport_error;reason=transport_error"), Is.EqualTo("kind=transport_error;reason=transport_error"));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=unsafe_destination;reason=unsafe_destination"), Is.EqualTo("kind=unsafe_destination;reason=unsafe_destination"));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=unknown;reason=unknown_failure"), Is.EqualTo("kind=unknown;reason=unknown_failure"));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary(" kind=unknown;reason=unknown_failure "), Is.EqualTo("kind=unknown;reason=unknown_failure"));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary(" "), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=unknown;reason=unknown_failure" + new string('x', AshlarSecurityEventWebhookOutboxBrowser.MaxLastErrorSummaryLength)), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("System.Exception: https://example.test?token=secret"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("=unknown;reason=unknown_failure"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=;reason=unknown_failure"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=invalid;reason=unknown_failure"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=unknown;status=abc;reason=unknown_failure"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=http_status;status=abc;reason=non_success_status"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=http_status;status=600;reason=non_success_status"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=http_status;status=99;reason=non_success_status"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=http_status;status=-1;reason=non_success_status"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=http_status;reason=secret"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=http_status;reason=transport_error"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=timeout;status=502;reason=delivery_timeout"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=unknown;kind=timeout;reason=unknown_failure"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=http_status;status=502;reason=non_success_status;extra=value"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=http_status;status=502"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("reason=unknown_failure"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=unknown;reason=unknown_failure\r\nx-test"), Is.Null);
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary("kind=unknown;reason=unknown_failure\nx-test"), Is.Null);
        }
    }

    [Test]
    public void ParseStatusHandlesMalformedProviderValues()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.ParseStatus(nameof(AshlarSecurityEventWebhookOutboxStatus.Failed)), Is.EqualTo(AshlarSecurityEventWebhookOutboxStatus.Failed));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.ParseStatus(null), Is.EqualTo(AshlarSecurityEventWebhookOutboxStatus.Pending));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.ParseStatus("unknown"), Is.EqualTo(AshlarSecurityEventWebhookOutboxStatus.Pending));
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.ParseStatus("99"), Is.EqualTo(AshlarSecurityEventWebhookOutboxStatus.Pending));
        }
    }

    [Test]
    public void FailureSummaryMapsExceptionsToSafePersistedDetails()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarSecurityEventWebhookOutboxFailureSummary.FromException(new HttpRequestException("https://example.test?token=secret", null, HttpStatusCode.BadGateway)).ToPersistedString(), Is.EqualTo("kind=http_status;status=502;reason=non_success_status"));
            Assert.That(new AshlarSecurityEventWebhookOutboxFailureSummary(AshlarSecurityEventWebhookOutboxFailureKind.HttpStatus, null, "non_success_status").ToPersistedString(), Is.EqualTo("kind=http_status;reason=non_success_status"));
            Assert.That(new AshlarSecurityEventWebhookOutboxFailureSummary(AshlarSecurityEventWebhookOutboxFailureKind.HttpStatus, 99, "non_success_status").ToPersistedString(), Is.EqualTo("kind=http_status;reason=non_success_status"));
            Assert.That(new AshlarSecurityEventWebhookOutboxFailureSummary(AshlarSecurityEventWebhookOutboxFailureKind.HttpStatus, 600, "non_success_status").ToPersistedString(), Is.EqualTo("kind=http_status;reason=non_success_status"));
            Assert.That(AshlarSecurityEventWebhookOutboxFailureSummary.FromException(new OperationCanceledException("https://example.test?token=secret")).ToPersistedString(), Is.EqualTo("kind=timeout;reason=delivery_timeout"));
            Assert.That(AshlarSecurityEventWebhookOutboxFailureSummary.Canceled().ToPersistedString(), Is.EqualTo("kind=canceled;reason=delivery_canceled"));
            Assert.That(AshlarSecurityEventWebhookOutboxFailureSummary.FromException(new AshlarSecurityEventWebhookUnsafeDestinationException("https://127.0.0.1/path?secret=value")).ToPersistedString(), Is.EqualTo("kind=unsafe_destination;reason=unsafe_destination"));
            Assert.That(AshlarSecurityEventWebhookOutboxFailureSummary.FromException(new HttpRequestException("https://example.test?token=secret")).ToPersistedString(), Is.EqualTo("kind=transport_error;reason=transport_error"));
            Assert.That(AshlarSecurityEventWebhookOutboxFailureSummary.FromException(new InvalidOperationException("https://example.test?token=secret")).ToPersistedString(), Is.EqualTo("kind=unknown;reason=unknown_failure"));
            Assert.That(new AshlarSecurityEventWebhookOutboxFailureSummary(AshlarSecurityEventWebhookOutboxFailureKind.Unknown, 599, "unsafe\r\nreason").ToPersistedString(), Is.EqualTo("kind=unknown;reason=unknown_failure"));
            Assert.That(new AshlarSecurityEventWebhookOutboxFailureSummary(AshlarSecurityEventWebhookOutboxFailureKind.Unknown, 99, "unknown_failure").ToPersistedString(), Is.EqualTo("kind=unknown;reason=unknown_failure"));
            Assert.That(new AshlarSecurityEventWebhookOutboxFailureSummary(AshlarSecurityEventWebhookOutboxFailureKind.Unknown, 600, "unknown_failure").ToPersistedString(), Is.EqualTo("kind=unknown;reason=unknown_failure"));
        }
    }

    [Test]
    public void FailureSummaryRejectsNullException()
    {
        Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookOutboxFailureSummary.FromException(null!));
    }

    [Test]
    public void DeliverySummaryDoesNotExposeSensitiveOutboxFields()
    {
        var propertyNames = typeof(AshlarSecurityEventWebhookOutboxDeliverySummary)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(propertyNames, Does.Not.Contain("Body"));
            Assert.That(propertyNames, Does.Not.Contain("Headers"));
            Assert.That(propertyNames, Does.Not.Contain("Uri"));
            Assert.That(propertyNames, Does.Not.Contain("SharedSecret"));
            Assert.That(propertyNames, Does.Not.Contain("LockedBy"));
        }
    }
}
