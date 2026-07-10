using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Resolves webhook destination host names for destination safety validation.
/// </summary>
public interface IAshlarSecurityEventWebhookDestinationResolver
{
    /// <summary>
    /// Resolves the host to IP addresses.
    /// </summary>
    /// <param name="host">The host name to resolve.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The resolved IP addresses.</returns>
    ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default);
}

/// <summary>
/// Uses system DNS to resolve webhook destination host names.
/// </summary>
public sealed class DnsAshlarSecurityEventWebhookDestinationResolver : IAshlarSecurityEventWebhookDestinationResolver
{
    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        return await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Validates security event webhook destinations before delivery.
/// </summary>
public sealed class AshlarSecurityEventWebhookDestinationValidator
{
    private readonly IAshlarSecurityEventWebhookDestinationResolver _resolver;
    private readonly AshlarSecurityEventWebhookDestinationPolicy _destinationPolicy;

    /// <summary>
    /// Initializes a new instance of the validator.
    /// </summary>
    /// <param name="resolver">The destination resolver.</param>
    /// <param name="options">The webhook options.</param>
    public AshlarSecurityEventWebhookDestinationValidator(
        IAshlarSecurityEventWebhookDestinationResolver resolver,
        IOptions<AshlarSecurityEventWebhookOptions>? options = null)
    {
        ArgumentNullException.ThrowIfNull(resolver);

        _resolver = resolver;
        _destinationPolicy = options?.Value.DestinationPolicy ?? AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly;
    }

    /// <summary>
    /// Validates a webhook destination <paramref name="uri" /> without performing DNS resolution.
    /// </summary>
    /// <param name="uri">The destination URI.</param>
    /// <returns>The validation result.</returns>
    public static AshlarSecurityEventWebhookDestinationValidationResult ValidateUri(Uri? uri)
    {
        return ValidateUri(uri, AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly);
    }

    /// <summary>
    /// Validates a webhook destination <paramref name="uri" /> without performing DNS resolution.
    /// </summary>
    /// <param name="uri">The destination URI.</param>
    /// <param name="destinationPolicy">The destination policy.</param>
    /// <returns>The validation result.</returns>
    public static AshlarSecurityEventWebhookDestinationValidationResult ValidateUri(
        Uri? uri,
        AshlarSecurityEventWebhookDestinationPolicy destinationPolicy)
    {
        if (uri is not { IsAbsoluteUri: true })
        {
            return AshlarSecurityEventWebhookDestinationValidationResult.Rejected("Webhook destination must be an absolute URI.");
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return AshlarSecurityEventWebhookDestinationValidationResult.Rejected("Webhook destination must use HTTPS.");
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            return AshlarSecurityEventWebhookDestinationValidationResult.Rejected("Webhook destination must not include user info.");
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            return AshlarSecurityEventWebhookDestinationValidationResult.Rejected("Webhook destination must not include a fragment.");
        }

        if (IsLocalhost(uri.Host))
        {
            return AshlarSecurityEventWebhookDestinationValidationResult.Rejected("Webhook destination host must not be localhost.");
        }

        if (IPAddress.TryParse(uri.Host, out var address) && IsBlockedAddress(address, destinationPolicy))
        {
            return AshlarSecurityEventWebhookDestinationValidationResult.Rejected("Webhook destination host resolves to a blocked address.");
        }

        return AshlarSecurityEventWebhookDestinationValidationResult.Valid;
    }

    /// <summary>
    /// Validates a webhook destination <paramref name="uri" />, including DNS resolution for host names.
    /// </summary>
    /// <param name="uri">The destination URI.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The validation result.</returns>
    public async ValueTask<AshlarSecurityEventWebhookDestinationValidationResult> ValidateAsync(
        Uri? uri,
        CancellationToken cancellationToken = default)
    {
        return (await ValidateAndResolveAllowedAddressesAsync(uri, cancellationToken).ConfigureAwait(false)).ValidationResult;
    }

    internal async ValueTask<IReadOnlyList<IPAddress>> ResolveAllowedAddressesAsync(
        string host,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        var addresses = await _resolver.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
        return addresses.Where(address => !IsBlockedAddress(address, _destinationPolicy)).ToArray();
    }

    internal AshlarSecurityEventWebhookDestinationValidationResult ValidateAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        return IsBlockedAddress(address, _destinationPolicy)
            ? AshlarSecurityEventWebhookDestinationValidationResult.Rejected("Webhook destination host resolves to a blocked address.")
            : AshlarSecurityEventWebhookDestinationValidationResult.Valid;
    }

    internal async ValueTask<AshlarSecurityEventWebhookResolvedDestinationValidation> ValidateAndResolveAllowedAddressesAsync(
        Uri? uri,
        CancellationToken cancellationToken = default)
    {
        var uriResult = ValidateUri(uri, _destinationPolicy);
        if (!uriResult.IsValid || uri is null)
        {
            return new AshlarSecurityEventWebhookResolvedDestinationValidation(uriResult, []);
        }

        if (IPAddress.TryParse(uri.Host, out var address))
        {
            return new AshlarSecurityEventWebhookResolvedDestinationValidation(uriResult, [address]);
        }

        var addresses = await _resolver.ResolveAsync(uri.Host, cancellationToken).ConfigureAwait(false);
        if (addresses.Count == 0)
        {
            return new AshlarSecurityEventWebhookResolvedDestinationValidation(
                AshlarSecurityEventWebhookDestinationValidationResult.Rejected("Webhook destination host did not resolve to an address."),
                []);
        }

        if (addresses.Any(address => IsBlockedAddress(address, _destinationPolicy)))
        {
            return new AshlarSecurityEventWebhookResolvedDestinationValidation(
                AshlarSecurityEventWebhookDestinationValidationResult.Rejected("Webhook destination host resolves to a blocked address."),
                []);
        }

        return new AshlarSecurityEventWebhookResolvedDestinationValidation(
            AshlarSecurityEventWebhookDestinationValidationResult.Valid,
            addresses);
    }

    internal static bool IsBlockedAddress(IPAddress address)
    {
        return IsBlockedAddress(address, AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly);
    }

    internal static bool IsBlockedAddress(IPAddress address, AshlarSecurityEventWebhookDestinationPolicy destinationPolicy)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            return IsBlockedAddress(address.MapToIPv4(), destinationPolicy);
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return IsBlockedIPv4(address.GetAddressBytes(), destinationPolicy);
        }

        return IsBlockedIPv6(address, destinationPolicy);
    }

    private static bool IsLocalhost(string host)
    {
        return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBlockedIPv4(byte[] bytes, AshlarSecurityEventWebhookDestinationPolicy destinationPolicy)
    {
        return bytes[0] == 0
            || bytes[0] == 127
            || bytes[0] == 169 && bytes[1] == 254
            || IsSpecialUseIPv4(bytes)
            || destinationPolicy != AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks && IsPrivateIPv4(bytes)
            || bytes[0] >= 224;
    }

    private static bool IsPrivateIPv4(byte[] bytes)
    {
        return bytes[0] == 10
            || bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31
            || bytes[0] == 192 && bytes[1] == 168;
    }

    private static bool IsSpecialUseIPv4(byte[] bytes)
    {
        return bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127
            || bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0
            || bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2
            || bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99
            || bytes[0] == 198 && bytes[1] >= 18 && bytes[1] <= 19
            || bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100
            || bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113;
    }

    private static bool IsBlockedIPv6(IPAddress address, AshlarSecurityEventWebhookDestinationPolicy destinationPolicy)
    {
        if (IPAddress.IPv6Loopback.Equals(address) || IPAddress.IPv6None.Equals(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 0xff
            || bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
            || destinationPolicy != AshlarSecurityEventWebhookDestinationPolicy.AllowPrivateNetworks && (bytes[0] & 0xfe) == 0xfc;
    }
}

/// <summary>
/// Creates SSRF-hardened HTTP handlers for Ashlar security event webhooks.
/// </summary>
public static class AshlarSecurityEventWebhookHttpMessageHandlerFactory
{
    internal delegate ValueTask<AshlarSecurityEventWebhookConnection> ConnectToAddressAsync(
        IPAddress address,
        int port,
        CancellationToken cancellationToken);

    /// <summary>
    /// Creates an HTTP handler that disables redirects and validates the connected IP address.
    /// </summary>
    /// <param name="destinationValidator">The webhook destination safety validator.</param>
    /// <returns>The HTTP message handler.</returns>
    public static HttpMessageHandler Create(AshlarSecurityEventWebhookDestinationValidator destinationValidator)
    {
        ArgumentNullException.ThrowIfNull(destinationValidator);

        return Create(destinationValidator, ConnectSocketToAddressAsync);
    }

    internal static HttpMessageHandler Create(
        AshlarSecurityEventWebhookDestinationValidator destinationValidator,
        ConnectToAddressAsync connectToAddressAsync)
    {
        ArgumentNullException.ThrowIfNull(destinationValidator);
        ArgumentNullException.ThrowIfNull(connectToAddressAsync);

        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = (context, cancellationToken) => ConnectAsync(
                context.DnsEndPoint,
                destinationValidator,
                connectToAddressAsync,
                cancellationToken)
        };
    }

    internal static async ValueTask<Stream> ConnectAsync(
        DnsEndPoint endPoint,
        AshlarSecurityEventWebhookDestinationValidator destinationValidator,
        ConnectToAddressAsync connectToAddressAsync,
        CancellationToken cancellationToken)
    {
        var destinationUriBuilder = new UriBuilder(Uri.UriSchemeHttps, endPoint.Host, endPoint.Port);
        var destinationValidation = await destinationValidator
            .ValidateAndResolveAllowedAddressesAsync(destinationUriBuilder.Uri, cancellationToken)
            .ConfigureAwait(false);
        if (!destinationValidation.ValidationResult.IsValid)
        {
            throw new AshlarSecurityEventWebhookUnsafeDestinationException(destinationValidation.ValidationResult.FailureReason);
        }

        Exception lastException = new AshlarSecurityEventWebhookUnsafeDestinationException("Webhook destination host did not resolve to an allowed address.");
        foreach (var address in destinationValidation.AllowedAddresses)
        {
            try
            {
                var connection = await connectToAddressAsync(address, endPoint.Port, cancellationToken).ConfigureAwait(false);
                return await ValidateConnectedStreamAsync(destinationValidator, connection).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not AshlarSecurityEventWebhookUnsafeDestinationException and not OperationCanceledException)
            {
                lastException = exception;
            }
        }

        throw lastException;
    }

    private static async ValueTask<Stream> ValidateConnectedStreamAsync(
        AshlarSecurityEventWebhookDestinationValidator destinationValidator,
        AshlarSecurityEventWebhookConnection connection)
    {
        try
        {
            var validation = destinationValidator.ValidateAddress(connection.RemoteAddress);
            if (!validation.IsValid)
            {
                throw new AshlarSecurityEventWebhookUnsafeDestinationException(validation.FailureReason);
            }

            return connection.Stream;
        }
        catch
        {
            await connection.Stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal static async ValueTask<AshlarSecurityEventWebhookConnection> ConnectSocketToAddressAsync(
        IPAddress address,
        int port,
        CancellationToken cancellationToken)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken).ConfigureAwait(false);
            return new AshlarSecurityEventWebhookConnection(
                new NetworkStream(socket, ownsSocket: true),
                address);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}

internal readonly record struct AshlarSecurityEventWebhookConnection(Stream Stream, IPAddress RemoteAddress);

internal sealed record AshlarSecurityEventWebhookResolvedDestinationValidation(
    AshlarSecurityEventWebhookDestinationValidationResult ValidationResult,
    IReadOnlyList<IPAddress> AllowedAddresses);

/// <summary>
/// Represents the result of webhook destination validation.
/// </summary>
/// <param name="IsValid">A value indicating whether the destination is valid.</param>
/// <param name="FailureReason">The safe failure reason, or an empty value when the destination is valid.</param>
public sealed record AshlarSecurityEventWebhookDestinationValidationResult(bool IsValid, string FailureReason)
{
    /// <summary>
    /// Gets the valid result.
    /// </summary>
    public static AshlarSecurityEventWebhookDestinationValidationResult Valid { get; } = new(true, string.Empty);

    /// <summary>
    /// Creates a rejected result.
    /// </summary>
    /// <param name="failureReason">The safe failure reason.</param>
    /// <returns>The rejected result.</returns>
    public static AshlarSecurityEventWebhookDestinationValidationResult Rejected(string failureReason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(failureReason);

        return new AshlarSecurityEventWebhookDestinationValidationResult(false, failureReason);
    }
}

/// <summary>
/// Represents an unsafe security event webhook destination.
/// </summary>
public sealed class AshlarSecurityEventWebhookUnsafeDestinationException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the exception.
    /// </summary>
    /// <param name="message">The safe exception message.</param>
    public AshlarSecurityEventWebhookUnsafeDestinationException(string message)
        : base(message)
    {
    }
}
