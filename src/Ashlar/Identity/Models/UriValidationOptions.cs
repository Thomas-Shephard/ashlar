namespace Ashlar.Identity.Models;

/// <summary>
/// Configuration options for URI validation.
/// </summary>
public sealed class UriValidationOptions
{
    /// <summary>
    /// Gets or sets the list of allowed callback URIs.
    /// URIs must match exactly or start with one of these prefixes.
    /// </summary>
    public IList<string> AllowedCallbackUris { get; set; } = [];

    /// <summary>
    /// Gets or sets whether null URIs are allowed.
    /// </summary>
    public bool AllowNull { get; set; }
}
