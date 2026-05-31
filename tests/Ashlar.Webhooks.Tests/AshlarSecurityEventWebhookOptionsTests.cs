using Ashlar.Auditing;
using Ashlar.Webhooks.SecurityEvents;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarSecurityEventWebhookOptionsTests
{
    [Test]
    public void ValidateAcceptsEmptyEndpointList()
    {
        Assert.That(AshlarSecurityEventWebhookOptions.Validate(new AshlarSecurityEventWebhookOptions()), Is.True);
    }

    [Test]
    public void OptionsDefaultsAreSafe()
    {
        var options = new AshlarSecurityEventWebhookOptions();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.Timeout, Is.EqualTo(TimeSpan.FromSeconds(10)));
            Assert.That(options.DestinationPolicy, Is.EqualTo(AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly));
        }
    }

    [TestCaseSource(nameof(InvalidOptions))]
    public void ValidateRejectsInvalidOptions(AshlarSecurityEventWebhookOptions? options)
    {
        Assert.That(AshlarSecurityEventWebhookOptions.Validate(options), Is.False);
    }

    [Test]
    public void EndpointValidateAcceptsHttpsEndpoint()
    {
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = new Uri("https://example.test/security-events"),
            SharedSecret = "shared-secret",
            Timeout = TimeSpan.FromSeconds(3)
        };
        endpoint.EventTypes.Add("ashlar.session.created");
        endpoint.Outcomes.Add(SecurityEventOutcomes.Success);

        Assert.That(AshlarSecurityEventWebhookEndpointOptions.Validate(endpoint), Is.True);
    }

    [Test]
    public void ValidateAllowsPrivateEndpointWhenPolicyExplicitlyAllowsPrivateNetworks()
    {
        var options = CreateOptions(new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "internal",
            Uri = new Uri("https://10.0.0.5/security-events"),
            SharedSecret = "shared-secret"
        });
        options.DestinationPolicy = AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks;

        Assert.That(AshlarSecurityEventWebhookOptions.Validate(options), Is.True);
    }

    [Test]
    public void EndpointDefaultsAreSafe()
    {
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(endpoint.Enabled, Is.True);
            Assert.That(endpoint.SharedSecret, Is.Null);
            Assert.That(endpoint.AllowUnsigned, Is.False);
            Assert.That(endpoint.Timeout, Is.Null);
            Assert.That(endpoint.EventTypes, Is.Empty);
            Assert.That(endpoint.Outcomes, Is.Empty);
        }
    }

    [Test]
    public void EndpointValidateAcceptsUnsignedOnlyWhenExplicitlyAllowed()
    {
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = new Uri("https://example.test/security-events"),
            AllowUnsigned = true
        };

        Assert.That(AshlarSecurityEventWebhookEndpointOptions.Validate(endpoint), Is.True);
    }

    private static IEnumerable<AshlarSecurityEventWebhookOptions?> InvalidOptions()
    {
        yield return null;
        yield return new AshlarSecurityEventWebhookOptions { Timeout = TimeSpan.Zero };
        yield return new AshlarSecurityEventWebhookOptions { DestinationPolicy = (AshlarSecurityEventWebhookDestinationPolicy)99 };
        yield return CreateOptions(null);
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = " ", Uri = new Uri("https://example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("http://example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("/relative", UriKind.Relative) });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://127.0.0.1") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test/path#fragment") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://user@example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), Timeout = TimeSpan.Zero });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit\r\nbad", Uri = new Uri("https://example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = " " });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test") });

        var blankEventType = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = "shared-secret" };
        blankEventType.EventTypes.Add(" ");
        yield return CreateOptions(blankEventType);

        var unsafeEventType = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = "shared-secret" };
        unsafeEventType.EventTypes.Add("ashlar.sign_in.failed\r\nx-test");
        yield return CreateOptions(unsafeEventType);

        var nullOutcome = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = "shared-secret" };
        nullOutcome.Outcomes.Add(null!);
        yield return CreateOptions(nullOutcome);

        var blankOutcome = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = "shared-secret" };
        blankOutcome.Outcomes.Add(" ");
        yield return CreateOptions(blankOutcome);

        var unsafeOutcome = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = "shared-secret" };
        unsafeOutcome.Outcomes.Add("success\r\nx-test");
        yield return CreateOptions(unsafeOutcome);
    }

    private static AshlarSecurityEventWebhookOptions CreateOptions(AshlarSecurityEventWebhookEndpointOptions? endpoint)
    {
        var options = new AshlarSecurityEventWebhookOptions();
        options.Endpoints.Add(endpoint!);
        return options;
    }
}
