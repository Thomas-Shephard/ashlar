namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines the provider-neutral status values for Ashlar operational diagnostics.
/// </summary>
public enum AshlarDiagnosticStatus
{
    /// <summary>
    /// The diagnostic target is healthy.
    /// </summary>
    Healthy = 0,

    /// <summary>
    /// The diagnostic target is available but operating with reduced capability.
    /// </summary>
    Degraded = 1,

    /// <summary>
    /// The diagnostic target is unhealthy.
    /// </summary>
    Unhealthy = 2,

    /// <summary>
    /// The diagnostic status could not be determined.
    /// </summary>
    Unknown = 3,

    /// <summary>
    /// The diagnostic check is not supported by the current provider or configuration.
    /// </summary>
    NotSupported = 4
}
