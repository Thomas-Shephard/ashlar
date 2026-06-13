using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Services;

/// <summary>
/// Default implementation of <see cref="IUriValidator"/>.
/// </summary>
public sealed class UriValidator : IUriValidator
{
    private readonly UriValidationOptions _options;
    private readonly List<Uri> _allowedUris;

    /// <summary>
    /// Initializes a new instance of the uri validator class.
    /// </summary>
    /// <param name="options">The options value.</param>
    public UriValidator(IOptions<UriValidationOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        _allowedUris = [];

        foreach (var allowedUri in _options.AllowedCallbackUris)
        {
            var parsed = CallbackUriAllowListEntry.Parse(allowedUri);
            if (parsed.Failure == CallbackUriAllowListEntryFailure.Blank)
            {
                continue;
            }

            if (parsed.Failure == CallbackUriAllowListEntryFailure.NotAbsoluteOrMalformed)
            {
                throw new InvalidOperationException($"The configured allowed callback URI '{allowedUri}' is not a valid absolute URI.");
            }

            if (parsed.Failure != CallbackUriAllowListEntryFailure.None)
            {
                throw new InvalidOperationException($"The configured allowed callback URI '{allowedUri}' must use http or https and must not include a query string or fragment.");
            }

            _allowedUris.Add(parsed.Uri!);
        }
    }

    /// <inheritdoc />
    public void ValidateOrThrow(Uri? uri)
    {
        if (!IsValid(uri))
        {
            throw new ArgumentException($"The URI '{uri}' is not allowed by the configured allowlist.", nameof(uri));
        }
    }

    /// <inheritdoc />
    public bool IsValid(Uri? uri)
    {
        if (uri == null)
        {
            return _options.AllowNull;
        }

        if (!CallbackUriAllowListEntry.IsSafeAbsoluteUri(uri))
        {
            return false;
        }

        var targetPath = uri.AbsolutePath.TrimEnd('/');

        return _allowedUris.Any(baseUri =>
        {
            if (!string.Equals(baseUri.Scheme, uri.Scheme, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(baseUri.Host, uri.Host, StringComparison.OrdinalIgnoreCase) ||
                baseUri.Port != uri.Port)
            {
                return false;
            }

            var basePath = baseUri.AbsolutePath.TrimEnd('/');

            if (targetPath.Equals(basePath, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (basePath.Length == 0)
            {
                return targetPath.Length == 0;
            }

            var basePathWithSlash = basePath + "/";
            return targetPath.StartsWith(basePathWithSlash, StringComparison.OrdinalIgnoreCase);
        });
    }

}

internal enum CallbackUriAllowListEntryFailure
{
    None,
    Blank,
    NotAbsoluteOrMalformed,
    UnsafeComponents
}

internal sealed record CallbackUriAllowListEntry(Uri? Uri, CallbackUriAllowListEntryFailure Failure)
{
    private static readonly HashSet<string> AllowedSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        Uri.UriSchemeHttps,
        Uri.UriSchemeHttp
    };

    public static CallbackUriAllowListEntry Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return new CallbackUriAllowListEntry(null, CallbackUriAllowListEntryFailure.Blank);
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return new CallbackUriAllowListEntry(null, CallbackUriAllowListEntryFailure.NotAbsoluteOrMalformed);
        }

        if (!IsSafeAbsoluteUri(uri))
        {
            return new CallbackUriAllowListEntry(uri, CallbackUriAllowListEntryFailure.UnsafeComponents);
        }

        return new CallbackUriAllowListEntry(uri, CallbackUriAllowListEntryFailure.None);
    }

    public static bool IsSafeAbsoluteUri(Uri uri)
    {
        return uri.IsAbsoluteUri &&
            AllowedSchemes.Contains(uri.Scheme) &&
            string.IsNullOrEmpty(uri.UserInfo) &&
            string.IsNullOrEmpty(uri.Query) &&
            string.IsNullOrEmpty(uri.Fragment);
    }
}
