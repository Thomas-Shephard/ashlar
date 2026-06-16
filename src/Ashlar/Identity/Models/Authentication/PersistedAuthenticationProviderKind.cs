namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Describes the persisted authentication provider shape represented by stored provider values.
/// </summary>
public enum PersistedAuthenticationProviderKind
{
    /// <summary>
    /// No provider values were persisted.
    /// </summary>
    None = 0,

    /// <summary>
    /// The persisted values identify a configured provider.
    /// </summary>
    Configured = 1,

    /// <summary>
    /// The persisted values contain the storage fallback marker used when a provider value was present but not configured.
    /// </summary>
    StorageFallback = 2,

    /// <summary>
    /// The persisted values contain a provider type without a usable provider name.
    /// </summary>
    Incomplete = 3
}
