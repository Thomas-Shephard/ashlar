using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Services;

/// <summary>
/// Default implementation of <see cref="IUriValidator"/>.
/// </summary>
public sealed class UriValidator : IUriValidator
{
    private readonly UriValidationOptions _options;
    private readonly List<Uri> _allowedUris;
    private static readonly HashSet<string> AllowedSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        Uri.UriSchemeHttps,
        Uri.UriSchemeHttp
    };

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
            if (string.IsNullOrWhiteSpace(allowedUri))
            {
                continue;
            }

            if (!Uri.TryCreate(allowedUri, UriKind.Absolute, out var baseUri))
            {
                throw new InvalidOperationException($"The configured allowed callback URI '{allowedUri}' is not a valid absolute URI.");
            }

            if (!IsSafeAbsoluteUri(baseUri))
            {
                throw new InvalidOperationException($"The configured allowed callback URI '{allowedUri}' must use http or https and must not include a query string or fragment.");
            }

            _allowedUris.Add(baseUri);
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

        if (!uri.IsAbsoluteUri)
        {
            return false;
        }

        if (!IsSafeAbsoluteUri(uri))
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

    private static bool IsSafeAbsoluteUri(Uri uri)
    {
        return uri.IsAbsoluteUri &&
            AllowedSchemes.Contains(uri.Scheme) &&
            string.IsNullOrEmpty(uri.UserInfo) &&
            string.IsNullOrEmpty(uri.Query) &&
            string.IsNullOrEmpty(uri.Fragment);
    }
}



