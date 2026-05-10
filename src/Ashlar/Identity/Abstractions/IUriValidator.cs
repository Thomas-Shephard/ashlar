namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Provides methods for validating URIs against an allowlist.
/// </summary>
public interface IUriValidator
{
    /// <summary>
    /// Validates the specified URI against the configured allowlist.
    /// Throws an InvalidOperationException if the URI is not valid.
    /// </summary>
    /// <param name="uri">The URI to validate.</param>
    void ValidateOrThrow(Uri? uri);

    /// <summary>
    /// Validates the specified URI against the configured allowlist.
    /// </summary>
    /// <param name="uri">The URI to validate.</param>
    /// <returns>True if the URI is valid; otherwise, false.</returns>
    bool IsValid(Uri? uri);
}
