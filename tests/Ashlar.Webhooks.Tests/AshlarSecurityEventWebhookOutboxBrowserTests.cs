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
    public void LastErrorSummaryIsNullSafeSingleLineAndTruncated()
    {
        var longError = "prefix\r\n" + new string('x', AshlarSecurityEventWebhookOutboxBrowser.MaxLastErrorSummaryLength + 10);
        var summary = AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary(longError);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarSecurityEventWebhookOutboxBrowser.CreateLastErrorSummary(null), Is.Null);
            Assert.That(summary, Has.Length.EqualTo(AshlarSecurityEventWebhookOutboxBrowser.MaxLastErrorSummaryLength));
            Assert.That(summary, Does.Not.Contain("\r"));
            Assert.That(summary, Does.Not.Contain("\n"));
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
