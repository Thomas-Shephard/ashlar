using System.Net;
using System.Net.Sockets;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.Options;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarSecurityEventWebhookDestinationValidatorTests
{
    [Test]
    public async Task ValidateAsyncAcceptsPublicHttpsDestination()
    {
        var validator = new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver(IPAddress.Parse("93.184.216.34")));

        var result = await validator.ValidateAsync(new Uri("https://example.test/security-events"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsValid, Is.True);
            Assert.That(result.FailureReason, Is.Empty);
        }
    }

    [TestCase("http://example.test/security-events")]
    [TestCase("https://localhost/security-events")]
    [TestCase("https://audit.localhost/security-events")]
    [TestCase("https://127.0.0.1/security-events")]
    [TestCase("https://[::1]/security-events")]
    [TestCase("https://10.0.0.1/security-events")]
    [TestCase("https://172.16.0.1/security-events")]
    [TestCase("https://172.31.255.255/security-events")]
    [TestCase("https://192.168.0.1/security-events")]
    [TestCase("https://100.64.0.1/security-events")]
    [TestCase("https://192.0.2.1/security-events")]
    [TestCase("https://198.18.0.1/security-events")]
    [TestCase("https://198.51.100.1/security-events")]
    [TestCase("https://203.0.113.1/security-events")]
    [TestCase("https://169.254.10.20/security-events")]
    [TestCase("https://224.0.0.1/security-events")]
    [TestCase("https://0.0.0.0/security-events")]
    [TestCase("https://[ff02::1]/security-events")]
    [TestCase("https://[::]/security-events")]
    [TestCase("https://[fd00::1]/security-events")]
    [TestCase("https://[fec0::1]/security-events")]
    [TestCase("https://[64:ff9b:1::1]/security-events")]
    [TestCase("https://[64:ff9b::7f00:1]/security-events")]
    [TestCase("https://[::ffff:10.0.0.1]/security-events")]
    [TestCase("https://user@example.test/security-events")]
    [TestCase("https://example.test/security-events#fragment")]
    public void ValidateUriRejectsUnsafeUriShapes(string uri)
    {
        var result = AshlarSecurityEventWebhookDestinationValidator.ValidateUri(new Uri(uri));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.FailureReason, Is.Not.Null.And.Not.Empty);
        }
    }

    [Test]
    public void ValidateUriRejectsMissingOrRelativeUri()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(AshlarSecurityEventWebhookDestinationValidator.ValidateUri(null).IsValid, Is.False);
            Assert.That(AshlarSecurityEventWebhookDestinationValidator.ValidateUri(new Uri("/security-events", UriKind.Relative)).IsValid, Is.False);
        }
    }

    [TestCase("10.0.0.5")]
    [TestCase("fec0::1")]
    [TestCase("64:ff9b:1::1")]
    [TestCase("64:ff9b::a00:1")]
    public async Task ValidateAsyncRejectsDnsResolvedUnsafeAddress(string address)
    {
        var validator = new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver(IPAddress.Parse(address)));

        var result = await validator.ValidateAsync(new Uri("https://example.test/security-events"));

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task AllowPrivateNetworksAcceptsPrivateDnsResolvedAddress()
    {
        var validator = new AshlarSecurityEventWebhookDestinationValidator(
            new StaticResolver(IPAddress.Parse("10.0.0.5")),
            Options.Create(new AshlarSecurityEventWebhookOptions
            {
                DestinationPolicy = AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks
            }));

        var result = await validator.ValidateAsync(new Uri("https://receiver.internal/security-events"));

        Assert.That(result.IsValid, Is.True);
    }

    [TestCase("https://10.0.0.1/security-events")]
    [TestCase("https://172.16.0.1/security-events")]
    [TestCase("https://192.168.0.1/security-events")]
    [TestCase("https://[::ffff:192.168.0.1]/security-events")]
    [TestCase("https://[fd00::1]/security-events")]
    [TestCase("https://[fec0::1]/security-events")]
    [TestCase("https://[64:ff9b:1:5db8:d8:2200::]/security-events")]
    [TestCase("https://[64:ff9b::a00:1]/security-events")]
    public void AllowPrivateNetworksAcceptsPrivateIpLiterals(string uri)
    {
        var result = AshlarSecurityEventWebhookDestinationValidator.ValidateUri(
            new Uri(uri),
            AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks);

        Assert.That(result.IsValid, Is.True);
    }

    [TestCase("https://127.0.0.1/security-events")]
    [TestCase("https://169.254.10.20/security-events")]
    [TestCase("https://100.64.0.1/security-events")]
    [TestCase("https://224.0.0.1/security-events")]
    [TestCase("https://0.0.0.0/security-events")]
    [TestCase("https://localhost/security-events")]
    [TestCase("https://[fe80::1]/security-events")]
    [TestCase("https://[64:ff9b::7f00:1]/security-events")]
    [TestCase("https://[64:ff9b::a9fe:1]/security-events")]
    [TestCase("https://[64:ff9b::e000:1]/security-events")]
    [TestCase("https://[64:ff9b::]/security-events")]
    [TestCase("https://[64:ff9b::6440:1]/security-events")]
    [TestCase("https://[64:ff9b::c000:201]/security-events")]
    public void AllowPrivateNetworksStillRejectsNonRoutableDestinations(string uri)
    {
        var result = AshlarSecurityEventWebhookDestinationValidator.ValidateUri(
            new Uri(uri),
            AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks);

        Assert.That(result.IsValid, Is.False);
    }

    [TestCase("64:ff9b::7f00:1")]
    [TestCase("64:ff9b::a9fe:1")]
    [TestCase("64:ff9b::e000:1")]
    [TestCase("64:ff9b::")]
    [TestCase("64:ff9b::6440:1")]
    [TestCase("64:ff9b::c000:201")]
    public async Task AllowPrivateNetworksRejectsUnsafeNat64DnsResolvedAddress(string address)
    {
        var validator = new AshlarSecurityEventWebhookDestinationValidator(
            new StaticResolver(IPAddress.Parse(address)),
            Options.Create(new AshlarSecurityEventWebhookOptions
            {
                DestinationPolicy = AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks
            }));

        var result = await validator.ValidateAsync(new Uri("https://receiver.internal/security-events"));

        Assert.That(result.IsValid, Is.False);
    }

    [TestCase("2001:db8::/32", "2001:db8:7f00:1::")]
    [TestCase("2001:db8:1200::/40", "2001:db8:127f:0:1::")]
    [TestCase("2001:db8:1234::/48", "2001:db8:1234:7f00:0:100::")]
    [TestCase("2001:db8:1234:5600::/56", "2001:db8:1234:567f:0:1::")]
    [TestCase("2001:db8:1234:5678::/64", "2001:db8:1234:5678:7f:0:100:0")]
    [TestCase("2001:db8:1234:5678:9abc:def0::/96", "2001:db8:1234:5678:9abc:def0:7f00:1")]
    public async Task ConfiguredNat64PrefixLengthsRejectEmbeddedLoopback(string prefix, string address)
    {
        var validator = CreateValidator(AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly, prefix, IPAddress.Parse(address));

        var result = await validator.ValidateAsync(new Uri("https://receiver.test/security-events"));

        Assert.That(result.IsValid, Is.False);
    }

    [TestCase("127.0.0.1", false, false)]
    [TestCase("169.254.1.1", false, false)]
    [TestCase("224.0.0.1", false, false)]
    [TestCase("0.0.0.0", false, false)]
    [TestCase("10.0.0.1", false, true)]
    [TestCase("93.184.216.34", true, true)]
    public async Task ConfiguredNat64AppliesDirectIPv4Policy(string embeddedAddress, bool publicInternetOnly, bool allowPrivateNetworks)
    {
        var address = $"2001:db8:1234:5678:9abc:def0:{IPAddress.Parse(embeddedAddress).GetAddressBytes()[0]:x2}{IPAddress.Parse(embeddedAddress).GetAddressBytes()[1]:x2}:{IPAddress.Parse(embeddedAddress).GetAddressBytes()[2]:x2}{IPAddress.Parse(embeddedAddress).GetAddressBytes()[3]:x2}";

        var publicResult = await CreateValidator(AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly, "2001:db8:1234:5678:9abc:def0::/96", IPAddress.Parse(address))
            .ValidateAsync(new Uri("https://receiver.test"));
        var privateResult = await CreateValidator(AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks, "2001:db8:1234:5678:9abc:def0::/96", IPAddress.Parse(address))
            .ValidateAsync(new Uri("https://receiver.test"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(publicResult.IsValid, Is.EqualTo(publicInternetOnly));
            Assert.That(privateResult.IsValid, Is.EqualTo(allowPrivateNetworks));
        }
    }

    [Test]
    public async Task ConfiguredNat64AppliesToIpLiteralAndConnectedPeer()
    {
        var address = IPAddress.Parse("2001:db8:1234:5678:9abc:def0:7f00:1");
        var validator = CreateValidator(AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly, "2001:db8:1234:5678:9abc:def0::/96");

        var literal = await validator.ValidateAsync(new Uri($"https://[{address}]/security-events"));
        var peer = validator.ValidateAddress(address);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(literal.IsValid, Is.False);
            Assert.That(peer.IsValid, Is.False);
        }
    }

    [Test]
    public async Task ConfiguredNat64UsesLongestMatchingPrefix()
    {
        var options = new AshlarSecurityEventWebhookOptions();
        options.Nat64Prefixes.Add(IPNetwork.Parse("2001:db8::/32"));
        options.Nat64Prefixes.Add(IPNetwork.Parse("2001:db8:5db8:d822::/96"));
        var validator = new AshlarSecurityEventWebhookDestinationValidator(
            new StaticResolver(IPAddress.Parse("2001:db8:5db8:d822::7f00:1")),
            Options.Create(options));

        var result = await validator.ValidateAsync(new Uri("https://receiver.test"));

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task ConfiguredNat64UsesLongestPrefixWithinBuiltInLocalUsePrefix()
    {
        var validator = CreateValidator(
            AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks,
            "64:ff9b:1:5db8:d822::/96",
            IPAddress.Parse("64:ff9b:1:5db8:d822::7f00:1"));

        var result = await validator.ValidateAsync(new Uri("https://receiver.test"));

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task ValidateAsyncRejectsDnsResolutionWithNoAddresses()
    {
        var validator = new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver());

        var result = await validator.ValidateAsync(new Uri("https://example.test/security-events"));

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public void ConstructorAndRejectedResultRejectNullArguments()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookDestinationValidator(null!));
            Assert.ThrowsAsync<ArgumentException>(() => new DnsAshlarSecurityEventWebhookDestinationResolver().ResolveAsync(" ").AsTask());
            Assert.Throws<ArgumentException>(() => AshlarSecurityEventWebhookDestinationValidationResult.Rejected(" "));
            Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookDestinationValidator.IsBlockedAddress(null!));
            Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookDestinationValidator.IsBlockedAddress(null!, AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly));
            Assert.ThrowsAsync<ArgumentException>(() => new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver()).ResolveAllowedAddressesAsync(" ").AsTask());
            Assert.Throws<ArgumentNullException>(() => new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver()).ValidateAddress(null!));
            Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookHttpMessageHandlerFactory.Create(null!));
            Assert.Throws<ArgumentNullException>(() => AshlarSecurityEventWebhookHttpMessageHandlerFactory.Create(
                new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver()),
                null!));
        }
    }

    [Test]
    public async Task ResolveAllowedAddressesFiltersBlockedAddresses()
    {
        var validator = new AshlarSecurityEventWebhookDestinationValidator(
            new StaticResolver(IPAddress.Parse("93.184.216.34"), IPAddress.Parse("10.0.0.5")));

        var addresses = await validator.ResolveAllowedAddressesAsync("example.test");

        Assert.That(addresses, Is.EqualTo(new[] { IPAddress.Parse("93.184.216.34") }));
    }

    [TestCase("93.184.216.34", true)]
    [TestCase("10.0.0.5", false)]
    public void ValidateAddressReturnsAddressSafetyResult(string address, bool expected)
    {
        var validator = new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver());

        var result = validator.ValidateAddress(IPAddress.Parse(address));

        Assert.That(result.IsValid, Is.EqualTo(expected));
    }

    [Test]
    public void HandlerConnectCallbackRejectsUnsafeDestinationBeforeConnecting()
    {
        var connected = false;
        var validator = new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver(IPAddress.Parse("127.0.0.1")));

        var exception = Assert.ThrowsAsync<AshlarSecurityEventWebhookUnsafeDestinationException>(
            () => InvokeConnectAsync(
                validator,
                (_, _, _) =>
                {
                    connected = true;
                    return ValueTask.FromResult(new AshlarSecurityEventWebhookConnection(new MemoryStream(), IPAddress.Parse("127.0.0.1")));
                },
                "localhost").AsTask());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.Not.Null);
            Assert.That(connected, Is.False);
        }
    }

    [Test]
    public async Task HandlerConnectCallbackAllowsPublicIpLiteralWithoutResolver()
    {
        var validator = new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver());
        var expectedAddress = IPAddress.Parse("93.184.216.34");
        var attempts = new List<IPAddress>();
        using var expectedStream = new MemoryStream();

        var stream = await InvokeConnectAsync(
            validator,
            (address, _, _) =>
            {
                attempts.Add(address);
                return ValueTask.FromResult(new AshlarSecurityEventWebhookConnection(expectedStream, address));
            },
            "93.184.216.34");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(stream, Is.SameAs(expectedStream));
            Assert.That(attempts, Is.EqualTo(new[] { expectedAddress }));
        }
    }

    [Test]
    public void HandlerFactoryCreatesHardenedSocketsHandler()
    {
        using var handler = (SocketsHttpHandler)AshlarSecurityEventWebhookHttpMessageHandlerFactory.Create(
            new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver(IPAddress.Parse("93.184.216.34"))),
            (_, _, _) =>
            {
                return ValueTask.FromResult(new AshlarSecurityEventWebhookConnection(new MemoryStream(), IPAddress.Parse("93.184.216.34")));
            });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(handler.AllowAutoRedirect, Is.False);
            Assert.That(handler.UseProxy, Is.False);
            Assert.That(handler.ConnectCallback, Is.Not.Null);
        }
    }

    [Test]
    public async Task HandlerConnectCallbackTriesNextAllowedAddressWhenConnectFails()
    {
        using var expectedStream = new MemoryStream();
        var firstAddress = IPAddress.Parse("93.184.216.34");
        var secondAddress = IPAddress.Parse("93.184.216.35");
        var attempts = new List<IPAddress>();
        var resolver = new CountingResolver(firstAddress, secondAddress);
        var validator = new AshlarSecurityEventWebhookDestinationValidator(resolver);

        var stream = await InvokeConnectAsync(
            validator,
            (address, _, _) =>
            {
                attempts.Add(address);
                if (address.Equals(firstAddress))
                {
                    throw new IOException("connection failed");
                }

                return ValueTask.FromResult(new AshlarSecurityEventWebhookConnection(expectedStream, address));
            },
            "example.test");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(stream, Is.SameAs(expectedStream));
            Assert.That(attempts, Is.EqualTo(new[] { firstAddress, secondAddress }));
            Assert.That(resolver.CallCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void HandlerConnectCallbackThrowsLastConnectFailureWhenAllAllowedAddressesFail()
    {
        var validator = new AshlarSecurityEventWebhookDestinationValidator(
            new StaticResolver(IPAddress.Parse("93.184.216.34"), IPAddress.Parse("93.184.216.35")));

        var exception = Assert.ThrowsAsync<InvalidOperationException>(
            () => InvokeConnectAsync(
                validator,
                (_, _, _) => throw new InvalidOperationException("last failure"),
                "example.test").AsTask());

        Assert.That(exception?.Message, Is.EqualTo("last failure"));
    }

    [Test]
    public async Task HandlerConnectCallbackReturnsConnectedStreamForAllowedDestination()
    {
        using var expectedStream = new MemoryStream();
        var validator = new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver(IPAddress.Parse("93.184.216.34")));

        var stream = await InvokeConnectAsync(
            validator,
            (_, _, _) => ValueTask.FromResult(new AshlarSecurityEventWebhookConnection(expectedStream, IPAddress.Parse("93.184.216.34"))),
            "example.test");

        Assert.That(stream, Is.SameAs(expectedStream));
    }

    [TestCase("10.0.0.5")]
    [TestCase("fec0::1")]
    [TestCase("64:ff9b:1::1")]
    [TestCase("64:ff9b::a9fe:1")]
    public async Task HandlerConnectCallbackDisposesStreamWhenConnectedAddressIsUnsafe(string address)
    {
        using var stream = new TrackingStream();
        var validator = new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver(IPAddress.Parse("93.184.216.34")));

        var exception = Assert.ThrowsAsync<AshlarSecurityEventWebhookUnsafeDestinationException>(
            () => InvokeConnectAsync(
                validator,
                (_, _, _) => ValueTask.FromResult(new AshlarSecurityEventWebhookConnection(stream, IPAddress.Parse(address))),
                "example.test").AsTask());

        await stream.DisposeTask.ConfigureAwait(false);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.Not.Null);
            Assert.That(stream.IsAsyncDisposed, Is.True);
        }
    }

    [TestCase("64:ff9b::7f00:1")]
    [TestCase("64:ff9b::a9fe:1")]
    [TestCase("64:ff9b::e000:1")]
    [TestCase("64:ff9b::")]
    [TestCase("64:ff9b::6440:1")]
    [TestCase("64:ff9b::c000:201")]
    public async Task AllowPrivateNetworksDisposesStreamWhenConnectedNat64AddressEmbedsUnsafeIPv4(string address)
    {
        using var stream = new TrackingStream();
        var validator = new AshlarSecurityEventWebhookDestinationValidator(
            new StaticResolver(IPAddress.Parse("10.0.0.5")),
            Options.Create(new AshlarSecurityEventWebhookOptions
            {
                DestinationPolicy = AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks
            }));

        var exception = Assert.ThrowsAsync<AshlarSecurityEventWebhookUnsafeDestinationException>(
            () => InvokeConnectAsync(
                validator,
                (_, _, _) => ValueTask.FromResult(new AshlarSecurityEventWebhookConnection(stream, IPAddress.Parse(address))),
                "receiver.internal").AsTask());

        await stream.DisposeTask.ConfigureAwait(false);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception, Is.Not.Null);
            Assert.That(stream.IsAsyncDisposed, Is.True);
        }
    }

    [Test]
    public async Task ConnectSocketToAddressAsyncConnectsToEndpoint()
    {
        using var listener = new TcpListener(IPAddress.Loopback, port: 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var acceptTask = listener.AcceptTcpClientAsync();

        var connection = await AshlarSecurityEventWebhookHttpMessageHandlerFactory.ConnectSocketToAddressAsync(
            IPAddress.Loopback,
            port,
            CancellationToken.None);

        using (connection.Stream)
        using (await acceptTask.ConfigureAwait(false))
        {
            using (Assert.EnterMultipleScope())
            {
                Assert.That(connection.RemoteAddress, Is.EqualTo(IPAddress.Loopback));
                Assert.That(connection.Stream.CanRead, Is.True);
            }
        }
    }

    [Test]
    public void ConnectSocketToAddressAsyncDisposesSocketWhenConnectFails()
    {
        using var listener = new TcpListener(IPAddress.Loopback, port: 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        Assert.ThrowsAsync<SocketException>(() => AshlarSecurityEventWebhookHttpMessageHandlerFactory.ConnectSocketToAddressAsync(
            IPAddress.Loopback,
            port,
            CancellationToken.None).AsTask());
    }

    [Test]
    public async Task DnsResolverResolvesHost()
    {
        var addresses = await new DnsAshlarSecurityEventWebhookDestinationResolver().ResolveAsync("localhost");

        Assert.That(addresses, Is.Not.Empty);
    }

    [TestCase("93.184.216.34", false)]
    [TestCase("169.253.10.20", false)]
    [TestCase("172.15.255.255", false)]
    [TestCase("172.32.0.0", false)]
    [TestCase("192.167.255.255", false)]
    [TestCase("223.255.255.255", false)]
    [TestCase("100.63.255.255", false)]
    [TestCase("100.64.0.0", true)]
    [TestCase("100.127.255.255", true)]
    [TestCase("100.128.0.0", false)]
    [TestCase("192.0.0.1", true)]
    [TestCase("192.0.1.1", false)]
    [TestCase("192.0.2.1", true)]
    [TestCase("192.88.98.1", false)]
    [TestCase("192.88.99.1", true)]
    [TestCase("192.88.100.1", false)]
    [TestCase("198.17.255.255", false)]
    [TestCase("198.18.0.0", true)]
    [TestCase("198.19.255.255", true)]
    [TestCase("198.20.0.0", false)]
    [TestCase("198.51.99.1", false)]
    [TestCase("198.51.100.1", true)]
    [TestCase("198.51.101.1", false)]
    [TestCase("203.0.112.1", false)]
    [TestCase("203.0.113.1", true)]
    [TestCase("203.0.114.1", false)]
    [TestCase("2001:4860:4860::8888", false)]
    [TestCase("fe00::1", false)]
    [TestCase("fe80::1", true)]
    [TestCase("fec0::", true)]
    [TestCase("fec0::1", true)]
    [TestCase("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true)]
    [TestCase("fd00::1", true)]
    [TestCase("64:ff9b:0:ffff:ffff:ffff:ffff:ffff", false)]
    [TestCase("64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff", false)]
    [TestCase("64:ff9b::7f00:1", true)]
    [TestCase("64:ff9b::a00:1", true)]
    [TestCase("64:ff9b::a9fe:1", true)]
    [TestCase("64:ff9b::c000:201", true)]
    [TestCase("64:ff9b::e000:1", true)]
    [TestCase("64:ff9b::5db8:d822", true)]
    [TestCase("64:ff9b:0:0:1::", false)]
    [TestCase("64:ff9b:1::", true)]
    [TestCase("64:ff9b:1::1", true)]
    [TestCase("64:ff9b:1:ffff:ffff:ffff:ffff:ffff", true)]
    [TestCase("64:ff9b:2::", false)]
    [TestCase("::ffff:192.168.0.1", true)]
    public void IsBlockedAddressClassifiesBoundaryAddresses(string address, bool expected)
    {
        Assert.That(AshlarSecurityEventWebhookDestinationValidator.IsBlockedAddress(IPAddress.Parse(address)), Is.EqualTo(expected));
    }

    private static ValueTask<Stream> InvokeConnectAsync(
        AshlarSecurityEventWebhookDestinationValidator validator,
        AshlarSecurityEventWebhookHttpMessageHandlerFactory.ConnectToAddressAsync connectToAddressAsync,
        string host)
    {
        return AshlarSecurityEventWebhookHttpMessageHandlerFactory.ConnectAsync(
            new DnsEndPoint(host, 443),
            validator,
            connectToAddressAsync,
            CancellationToken.None);
    }

    private static AshlarSecurityEventWebhookDestinationValidator CreateValidator(
        AshlarSecurityEventWebhookDestinationPolicy policy,
        string prefix,
        params IPAddress[] addresses)
    {
        var options = new AshlarSecurityEventWebhookOptions { DestinationPolicy = policy };
        options.Nat64Prefixes.Add(IPNetwork.Parse(prefix));
        return new AshlarSecurityEventWebhookDestinationValidator(new StaticResolver(addresses), Options.Create(options));
    }

    private sealed class StaticResolver(params IPAddress[] addresses) : IAshlarSecurityEventWebhookDestinationResolver
    {
        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult<IReadOnlyList<IPAddress>>(addresses);
        }
    }

    private sealed class CountingResolver(params IPAddress[] addresses) : IAshlarSecurityEventWebhookDestinationResolver
    {
        public int CallCount { get; private set; }

        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
        {
            CallCount++;

            return ValueTask.FromResult<IReadOnlyList<IPAddress>>(addresses);
        }
    }

    private sealed class TrackingStream : MemoryStream
    {
        private readonly TaskCompletionSource _disposeCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool IsAsyncDisposed { get; private set; }

        public Task DisposeTask => _disposeCompletion.Task;

        public override ValueTask DisposeAsync()
        {
            IsAsyncDisposed = true;
            _disposeCompletion.SetResult();
            return base.DisposeAsync();
        }
    }
}
