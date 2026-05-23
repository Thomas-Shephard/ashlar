namespace Ashlar.OAuth;

/// <summary>
/// Describes the outcome of linking a validated external account to an existing Ashlar user.
/// </summary>
/// <param name="Status">The link outcome status.</param>
/// <param name="Assertion">The mapped external identity assertion, when mapping succeeded.</param>
/// <param name="CredentialLink">The underlying credential link result, when credential linking was attempted.</param>
public sealed record AshlarExternalAccountLinkResult(
    AshlarExternalAccountLinkStatus Status,
    ExternalIdentityAssertion? Assertion = null,
    Result? CredentialLink = null)
{
    /// <summary>
    /// Gets a value indicating whether a credential was newly linked.
    /// </summary>
    public bool Linked => Status == AshlarExternalAccountLinkStatus.Linked;

    /// <summary>
    /// Gets a value indicating whether the requested external account is already linked to the same user.
    /// </summary>
    public bool AlreadyLinked => Status == AshlarExternalAccountLinkStatus.AlreadyLinked;
}

/// <summary>
/// Enumerates safe result states for external account linking.
/// </summary>
public enum AshlarExternalAccountLinkStatus
{
    /// <summary>
    /// The external account was linked to the current Ashlar user.
    /// </summary>
    Linked,

    /// <summary>
    /// The external account was already linked to the same Ashlar user.
    /// </summary>
    AlreadyLinked,

    /// <summary>
    /// The requested provider is not configured.
    /// </summary>
    UnsupportedProvider,

    /// <summary>
    /// The external authentication ticket could not be completed.
    /// </summary>
    AuthenticationFailed,

    /// <summary>
    /// The external authentication ticket did not match the requested provider.
    /// </summary>
    ProviderMismatch,

    /// <summary>
    /// The external principal was missing required identity data.
    /// </summary>
    InvalidPrincipal,

    /// <summary>
    /// The external account is already linked to another Ashlar user.
    /// </summary>
    AlreadyLinkedToAnotherUser,

    /// <summary>
    /// The credential could not be linked.
    /// </summary>
    Failed
}
