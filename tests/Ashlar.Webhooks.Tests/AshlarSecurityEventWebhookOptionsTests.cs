using Ashlar.Auditing;
using Ashlar.Webhooks.SecurityEvents;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarSecurityEventWebhookOptionsTests
{
    private const string ValidSecret = "0123456789abcdef0123456789abcdef";

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

    [TestCase(32)]
    [TestCase(40)]
    [TestCase(48)]
    [TestCase(56)]
    [TestCase(64)]
    [TestCase(96)]
    public void ValidateAcceptsRfc6052Nat64PrefixLengths(int prefixLength)
    {
        var options = new AshlarSecurityEventWebhookOptions();
        options.Nat64Prefixes.Add(new System.Net.IPNetwork(System.Net.IPAddress.Parse("2001:db8::"), prefixLength));

        Assert.That(AshlarSecurityEventWebhookOptions.Validate(options), Is.True);
    }

    [Test]
    public void EndpointValidateAcceptsHttpsEndpoint()
    {
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = new Uri("https://example.test/security-events"),
            SharedSecret = ValidSecret,
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
            SharedSecret = ValidSecret
        });
        options.DestinationPolicy = AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks;

        Assert.That(AshlarSecurityEventWebhookOptions.Validate(options), Is.True);
    }

    [Test]
    public void ValidateRejectsDuplicateEndpointNames()
    {
        var options = CreateOptions(CreateValidEndpoint("audit"));
        options.Endpoints.Add(CreateValidEndpoint("audit"));

        Assert.That(AshlarSecurityEventWebhookOptions.Validate(options), Is.False);
    }

    [Test]
    public void ValidateComparesEndpointNamesOrdinally()
    {
        var options = CreateOptions(CreateValidEndpoint("audit"));
        options.Endpoints.Add(CreateValidEndpoint("Audit"));

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

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("0123456789abcdef0123456789abcde")]
    public void EndpointValidateRejectsBlankAndShortSharedSecrets(string sharedSecret)
    {
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = new Uri("https://example.test/security-events"),
            SharedSecret = sharedSecret,
            AllowUnsigned = true
        };

        Assert.That(AshlarSecurityEventWebhookEndpointOptions.Validate(endpoint), Is.False);
    }

    [Test]
    public void EndpointValidateMeasuresSharedSecretAsUtf8Bytes()
    {
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = new Uri("https://example.test/security-events"),
            SharedSecret = new string('\u00e9', 15)
        };

        Assert.That(AshlarSecurityEventWebhookEndpointOptions.Validate(endpoint), Is.False);

        endpoint.SharedSecret += '\u00e9';

        Assert.That(AshlarSecurityEventWebhookEndpointOptions.Validate(endpoint), Is.True);
    }

    private static IEnumerable<AshlarSecurityEventWebhookOptions?> InvalidOptions()
    {
        yield return null;
        yield return new AshlarSecurityEventWebhookOptions { Timeout = TimeSpan.Zero };
        yield return new AshlarSecurityEventWebhookOptions { DestinationPolicy = (AshlarSecurityEventWebhookDestinationPolicy)99 };
        var invalidNat64Length = new AshlarSecurityEventWebhookOptions();
        invalidNat64Length.Nat64Prefixes.Add(System.Net.IPNetwork.Parse("2001:db8::/65"));
        yield return invalidNat64Length;
        var ipv4Nat64Prefix = new AshlarSecurityEventWebhookOptions();
        ipv4Nat64Prefix.Nat64Prefixes.Add(System.Net.IPNetwork.Parse("192.0.2.0/32"));
        yield return ipv4Nat64Prefix;
        var nonZeroReservedOctet = new AshlarSecurityEventWebhookOptions();
        nonZeroReservedOctet.Nat64Prefixes.Add(System.Net.IPNetwork.Parse("2001:db8:1234:5678:100::/96"));
        yield return nonZeroReservedOctet;
        yield return CreateOptions(null);
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = " ", Uri = new Uri("https://example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("http://example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("/relative", UriKind.Relative) });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://127.0.0.1") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test/path#fragment") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://user@example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), Timeout = TimeSpan.Zero });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit\r\nbad", Uri = new Uri("https://example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test") });

        var blankEventType = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = ValidSecret };
        blankEventType.EventTypes.Add(" ");
        yield return CreateOptions(blankEventType);

        var unsafeEventType = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = ValidSecret };
        unsafeEventType.EventTypes.Add("ashlar.sign_in.failed\r\nx-test");
        yield return CreateOptions(unsafeEventType);

        var nullOutcome = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = ValidSecret };
        nullOutcome.Outcomes.Add(null!);
        yield return CreateOptions(nullOutcome);

        var blankOutcome = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = ValidSecret };
        blankOutcome.Outcomes.Add(" ");
        yield return CreateOptions(blankOutcome);

        var unsafeOutcome = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = ValidSecret };
        unsafeOutcome.Outcomes.Add("success\r\nx-test");
        yield return CreateOptions(unsafeOutcome);
    }

    private static AshlarSecurityEventWebhookOptions CreateOptions(AshlarSecurityEventWebhookEndpointOptions? endpoint)
    {
        var options = new AshlarSecurityEventWebhookOptions();
        options.Endpoints.Add(endpoint!);
        return options;
    }

    private static AshlarSecurityEventWebhookEndpointOptions CreateValidEndpoint(string name) => new()
    {
        Name = name,
        Uri = new Uri("https://example.test/security-events"),
        SharedSecret = ValidSecret
    };
}
