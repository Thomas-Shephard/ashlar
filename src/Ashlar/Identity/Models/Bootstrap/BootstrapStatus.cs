namespace Ashlar.Identity.Models.Bootstrap;

/// <summary>
/// Lists whether first-administrator bootstrap has completed.
/// </summary>
public enum BootstrapStatus
{
    /// <summary>
    /// Bootstrap has not completed and first-admin setup may still be available.
    /// </summary>
    Uninitialized,
    /// <summary>
    /// Bootstrap has completed and first-admin setup should no longer be accepted.
    /// </summary>
    Initialized
}
