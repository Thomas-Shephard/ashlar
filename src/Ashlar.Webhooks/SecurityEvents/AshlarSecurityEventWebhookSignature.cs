using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Defines signature verification outcomes for Ashlar security event webhook requests.
/// </summary>
public enum AshlarSecurityEventWebhookVerificationStatus
{
    /// <summary>
    /// The request signature is valid.
    /// </summary>
    Valid = 0,

    /// <summary>
    /// The signature header is missing.
    /// </summary>
    MissingSignature = 1,

    /// <summary>
    /// The signature header is malformed.
    /// </summary>
    MalformedSignature = 2,

    /// <summary>
    /// The signature timestamp header is missing.
    /// </summary>
    MissingTimestamp = 3,

    /// <summary>
    /// The signature timestamp is outside the accepted tolerance.
    /// </summary>
    TimestampOutsideTolerance = 4,

    /// <summary>
    /// The request signature does not match the expected signature.
    /// </summary>
    InvalidSignature = 5,

    /// <summary>
    /// The shared secret required for verification is missing.
    /// </summary>
    MissingSecret = 6,

    /// <summary>
    /// The event occurrence timestamp header is missing.
    /// </summary>
    MissingEventTimestamp = 7,

    /// <summary>
    /// The event occurrence timestamp header is malformed.
    /// </summary>
    MalformedEventTimestamp = 8
}

/// <summary>
/// Configures receiver-side Ashlar security event webhook signature verification.
/// </summary>
public sealed class AshlarSecurityEventWebhookVerificationOptions
{
    /// <summary>
    /// Gets or sets the accepted clock skew for webhook signatures.
    /// </summary>
    public TimeSpan TimestampTolerance { get; set; } = TimeSpan.FromMinutes(5);
}

/// <summary>
/// Represents an Ashlar security event webhook signature verification result.
/// </summary>
/// <param name="Status">The explicit verification status.</param>
public sealed record AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus Status)
{
    /// <summary>
    /// Gets a value indicating whether the signature is valid.
    /// </summary>
    public bool IsValid => Status == AshlarSecurityEventWebhookVerificationStatus.Valid;

    /// <summary>
    /// Gets a safe failure reason suitable for logs and public diagnostics.
    /// </summary>
    public string FailureReason => Status switch
    {
        AshlarSecurityEventWebhookVerificationStatus.Valid => string.Empty,
        AshlarSecurityEventWebhookVerificationStatus.MissingSignature => "Missing signature.",
        AshlarSecurityEventWebhookVerificationStatus.MalformedSignature => "Malformed signature.",
        AshlarSecurityEventWebhookVerificationStatus.MissingTimestamp => "Missing signature timestamp.",
        AshlarSecurityEventWebhookVerificationStatus.TimestampOutsideTolerance => "Signature timestamp is outside the accepted tolerance.",
        AshlarSecurityEventWebhookVerificationStatus.InvalidSignature => "Invalid signature.",
        AshlarSecurityEventWebhookVerificationStatus.MissingSecret => "Missing shared secret.",
        AshlarSecurityEventWebhookVerificationStatus.MissingEventTimestamp => "Missing event timestamp.",
        AshlarSecurityEventWebhookVerificationStatus.MalformedEventTimestamp => "Malformed event timestamp.",
        _ => "Invalid signature."
    };

    /// <summary>
    /// Gets the valid verification result.
    /// </summary>
    public static AshlarSecurityEventWebhookVerificationResult Valid { get; } = new(AshlarSecurityEventWebhookVerificationStatus.Valid);
}

/// <summary>
/// Groups receiver-side inputs needed to verify an Ashlar security event webhook request.
/// </summary>
public sealed class AshlarSecurityEventWebhookVerificationRequest
{
    /// <summary>
    /// Gets the raw request body bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Body { get; init; }

    /// <summary>
    /// Gets the relevant request headers.
    /// </summary>
    public required IReadOnlyDictionary<string, string> Headers { get; init; }

    /// <summary>
    /// Gets the shared secret.
    /// </summary>
    public string? SharedSecret { get; init; }

    /// <summary>
    /// Gets the expected event identifier.
    /// </summary>
    public Guid EventId { get; init; }

    /// <summary>
    /// Gets the endpoint name or identity.
    /// </summary>
    public required string EndpointName { get; init; }

    /// <summary>
    /// Gets the canonical destination path and query component.
    /// </summary>
    public required string DestinationPathAndQuery { get; init; }

    /// <summary>
    /// Gets the current time provider.
    /// </summary>
    public required TimeProvider TimeProvider { get; init; }

    /// <summary>
    /// Gets optional verification options.
    /// </summary>
    public AshlarSecurityEventWebhookVerificationOptions? Options { get; init; }
}

/// <summary>
/// Creates and verifies Ashlar security event webhook signatures.
/// </summary>
public static class AshlarSecurityEventWebhookSignature
{
    /// <summary>
    /// Defines the signature header name.
    /// </summary>
    public const string SignatureHeaderName = "X-Ashlar-Signature";

    /// <summary>
    /// Defines the signature timestamp header name.
    /// </summary>
    public const string SignatureTimestampHeaderName = "X-Ashlar-Signature-Timestamp";

    /// <summary>
    /// Defines the event occurrence timestamp header name.
    /// </summary>
    public const string EventTimestampHeaderName = "X-Ashlar-Timestamp";

    /// <summary>
    /// Defines the current signature version.
    /// </summary>
    public const string SignatureVersion = "v1";

    private const string SignedPayloadPrefix = "ashlar-security-event-webhook/v1";
    private const int Sha256HexLength = 64;

    /// <summary>
    /// Creates the versioned HMAC-SHA256 signature for a webhook request.
    /// </summary>
    /// <param name="sharedSecret">The shared secret.</param>
    /// <param name="body">The raw request body bytes.</param>
    /// <param name="signatureTimestamp">The signature timestamp.</param>
    /// <param name="occurredAt">The security event occurrence timestamp.</param>
    /// <param name="eventId">The security event identifier.</param>
    /// <param name="endpointName">The endpoint name or identity.</param>
    /// <param name="destinationPathAndQuery">The canonical destination path and query component.</param>
    /// <returns>The formatted signature header value.</returns>
    public static string CreateSignature(
        string sharedSecret,
        ReadOnlySpan<byte> body,
        DateTimeOffset signatureTimestamp,
        DateTimeOffset occurredAt,
        Guid eventId,
        string endpointName,
        string destinationPathAndQuery)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);
        ValidateSigningInputs(endpointName, destinationPathAndQuery);

        var hash = ComputeSignatureHash(sharedSecret, body, signatureTimestamp, occurredAt, eventId, endpointName, destinationPathAndQuery);
        return string.Concat(SignatureVersion, "=", ToLowerHex(hash));
    }

    /// <summary>
    /// Verifies an Ashlar security event webhook request signature.
    /// </summary>
    /// <param name="request">The verification request.</param>
    /// <returns>The verification result.</returns>
    public static AshlarSecurityEventWebhookVerificationResult Verify(AshlarSecurityEventWebhookVerificationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Headers);
        ArgumentNullException.ThrowIfNull(request.TimeProvider);
        ValidateSigningInputs(request.EndpointName, request.DestinationPathAndQuery);

        if (string.IsNullOrWhiteSpace(request.SharedSecret))
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MissingSecret);
        }

        if (!TryGetHeader(request.Headers, SignatureTimestampHeaderName, out var timestampValue))
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MissingTimestamp);
        }

        if (!long.TryParse(timestampValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unixSeconds))
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MalformedSignature);
        }

        DateTimeOffset signatureTimestamp;
        try
        {
            signatureTimestamp = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MalformedSignature);
        }

        if (!string.Equals(timestampValue, FormatTimestamp(signatureTimestamp), StringComparison.Ordinal))
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MalformedSignature);
        }

        var tolerance = request.Options?.TimestampTolerance ?? TimeSpan.FromMinutes(5);
        if (tolerance < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Timestamp tolerance must not be negative.");
        }

        var now = request.TimeProvider.GetUtcNow();
        if (signatureTimestamp < now.Subtract(tolerance) || signatureTimestamp > now.Add(tolerance))
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.TimestampOutsideTolerance);
        }

        if (!TryGetHeader(request.Headers, EventTimestampHeaderName, out var occurredAtValue))
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MissingEventTimestamp);
        }

        if (!DateTimeOffset.TryParseExact(
            occurredAtValue,
            "O",
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var occurredAt))
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MalformedEventTimestamp);
        }

        if (!TryGetHeader(request.Headers, SignatureHeaderName, out var signatureValue))
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MissingSignature);
        }

        if (!TryParseSignature(signatureValue, out var actualSignature))
        {
            return new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.MalformedSignature);
        }

        var expectedSignature = ComputeSignatureHash(
            request.SharedSecret,
            request.Body.Span,
            signatureTimestamp,
            occurredAt,
            request.EventId,
            request.EndpointName,
            request.DestinationPathAndQuery);
        return CryptographicOperations.FixedTimeEquals(actualSignature, expectedSignature)
            ? AshlarSecurityEventWebhookVerificationResult.Valid
            : new AshlarSecurityEventWebhookVerificationResult(AshlarSecurityEventWebhookVerificationStatus.InvalidSignature);
    }

    /// <summary>
    /// Creates the canonical destination component used for signing.
    /// </summary>
    /// <param name="uri">The absolute webhook URI.</param>
    /// <returns>The path and query component.</returns>
    public static string CreateCanonicalDestination(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return uri.PathAndQuery;
    }

    /// <summary>
    /// Creates the Unix timestamp value used by the signature timestamp header.
    /// </summary>
    /// <param name="signatureTimestamp">The signature timestamp.</param>
    /// <returns>The header value.</returns>
    public static string FormatTimestamp(DateTimeOffset signatureTimestamp)
    {
        return signatureTimestamp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
    }

    private static void ValidateSigningInputs(string endpointName, string destinationPathAndQuery)
    {
        AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
            endpointName,
            nameof(endpointName),
            "Endpoint name is required.",
            "Endpoint name must not contain line breaks.");
        if (string.IsNullOrWhiteSpace(destinationPathAndQuery))
        {
            throw new ArgumentException("Destination path and query is required.", nameof(destinationPathAndQuery));
        }

        if (!AshlarSecurityEventWebhookHeaderValues.IsSafe(destinationPathAndQuery))
        {
            throw new ArgumentException("Destination path and query must not contain line breaks.", nameof(destinationPathAndQuery));
        }
    }

    private static string CreateSignedPayload(
        ReadOnlySpan<byte> body,
        DateTimeOffset signatureTimestamp,
        DateTimeOffset occurredAt,
        Guid eventId,
        string endpointName,
        string destinationPathAndQuery)
    {
        var fields = new[]
        {
            SignedPayloadPrefix,
            FormatTimestamp(signatureTimestamp),
            occurredAt.ToString("O"),
            eventId.ToString("D"),
            endpointName,
            destinationPathAndQuery,
            ComputeSha256Hex(body)
        };
        var builder = new StringBuilder();
        foreach (var field in fields)
        {
            builder.Append(field.Length.ToString(CultureInfo.InvariantCulture));
            builder.Append(':');
            builder.Append(field);
            builder.Append('\n');
        }

        return builder.ToString();
    }

    private static byte[] ComputeSignatureHash(
        string sharedSecret,
        ReadOnlySpan<byte> body,
        DateTimeOffset signatureTimestamp,
        DateTimeOffset occurredAt,
        Guid eventId,
        string endpointName,
        string destinationPathAndQuery)
    {
        var secretBytes = Encoding.UTF8.GetBytes(sharedSecret);
        var signedPayload = CreateSignedPayload(body, signatureTimestamp, occurredAt, eventId, endpointName, destinationPathAndQuery);
        return HMACSHA256.HashData(secretBytes, Encoding.UTF8.GetBytes(signedPayload));
    }

    private static string ComputeSha256Hex(ReadOnlySpan<byte> value)
    {
        var hash = SHA256.HashData(value);
        return ToLowerHex(hash);
    }

    private static string ToLowerHex(ReadOnlySpan<byte> value)
    {
#if NET9_0_OR_GREATER
        return Convert.ToHexStringLower(value);
#else
        return Convert.ToHexString(value).ToLowerInvariant();
#endif
    }

    private static bool TryGetHeader(IReadOnlyDictionary<string, string> headers, string name, out string value)
    {
        if (headers.TryGetValue(name, out var exactValue))
        {
            value = exactValue;
            return true;
        }

        var matchedValue = headers
            .Where(header => string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase))
            .Select(header => header.Value)
            .FirstOrDefault();

        if (matchedValue is not null)
        {
            value = matchedValue;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool TryParseSignature(string? value, out byte[] signature)
    {
        signature = [];
        if (string.IsNullOrWhiteSpace(value) || !value.StartsWith(SignatureVersion + "=", StringComparison.Ordinal))
        {
            return false;
        }

        var hex = value[(SignatureVersion.Length + 1)..];
        if (hex.Length != Sha256HexLength)
        {
            return false;
        }

        try
        {
            signature = Convert.FromHexString(hex);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
