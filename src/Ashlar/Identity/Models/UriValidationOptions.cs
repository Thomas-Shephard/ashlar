namespace Ashlar.Identity.Models;

/// <summary>
/// Configuration options for URI validation.
/// </summary>
public sealed class UriValidationOptions
{
    /// <summary>
    /// Gets or sets the list of allowed callback URIs.
    /// Entries must be absolute http or https URIs without query strings or fragments.
    /// Candidate callback URIs must match the configured scheme, host, port, and path
    /// exactly or be below the configured path on a segment boundary.
    /// </summary>
    /// <remarks>
    /// For example, allowing https://app.example.com/account permits
    /// https://app.example.com/account and https://app.example.com/account/verify,
    /// but rejects https://app.example.com/accounting. Allowing
    /// https://app.example.com permits only the root callback path.
    /// </remarks>
    public IList<string> AllowedCallbackUris { get; set; } = [];

    /// <summary>
    /// Gets or sets whether <see langword="null" /> URIs are allowed. Token-bearing
    /// callback flows should keep this disabled.
    /// </summary>
    public bool AllowNull { get; set; }
}
