using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

/// <summary>
/// Default implementation of <see cref="IUriValidator"/>.
/// </summary>
public sealed class UriValidator : IUriValidator
{
    private readonly UriValidationOptions _options;
    private readonly List<Uri> _allowedUris;

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

        return _allowedUris.Any(baseUri =>
        {
            if (!string.Equals(baseUri.Scheme, uri.Scheme, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(baseUri.Host, uri.Host, StringComparison.OrdinalIgnoreCase) ||
                baseUri.Port != uri.Port)
            {
                return false;
            }

            var basePath = baseUri.AbsolutePath.TrimEnd('/');
            var targetPath = uri.AbsolutePath.TrimEnd('/');

            // Exact match (ignoring trailing slash)
            if (targetPath.Equals(basePath, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Sub-path match. Ensure the base path is followed by a slash.
            // Example: base is /app, target is /app/callback
            var basePathWithSlash = basePath + "/";
            return uri.AbsolutePath.StartsWith(basePathWithSlash, StringComparison.OrdinalIgnoreCase);
        });
    }
}
