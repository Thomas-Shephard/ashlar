namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides methods for validating URIs against an allowlist.
/// </summary>
public interface IUriValidator
{
    /// <summary>
    /// Validates the specified <paramref name="uri" /> against the configured allowlist.
    /// Throws an InvalidOperationException if the <paramref name="uri" /> is not valid.
    /// </summary>
    /// <param name="uri">The URI to validate before using it in a callback or redirect flow.</param>
    void ValidateOrThrow(Uri? uri);

    /// <summary>
    /// Validates the specified <paramref name="uri" /> against the configured allowlist.
    /// </summary>
    /// <param name="uri">The URI to validate before using it in a callback or redirect flow.</param>
    /// <returns><see langword="true" /> when the supplied value is allowed by configuration.</returns>
    bool IsValid(Uri? uri);
}
