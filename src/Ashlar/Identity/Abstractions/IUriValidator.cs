namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Provides methods for validating URIs against an allowlist.
/// </summary>
public interface IUriValidator
{
    /// <summary>
    /// Validates the specified <paramref name="uri" /> against the configured allowlist.
    /// Throws an InvalidOperationException if the <paramref name="uri" /> is not valid.
    /// </summary>
    /// <param name="uri">The uri value.</param>
    void ValidateOrThrow(Uri? uri);

    /// <summary>
    /// Validates the specified <paramref name="uri" /> against the configured allowlist.
    /// </summary>
    /// <param name="uri">The uri value.</param>
    /// <returns>The operation result.</returns>
    bool IsValid(Uri? uri);
}
