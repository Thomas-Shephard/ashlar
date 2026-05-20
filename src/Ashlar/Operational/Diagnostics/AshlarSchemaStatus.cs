namespace Ashlar.Operational.Diagnostics;

/// <summary>
/// Defines provider-neutral schema status values for Ashlar storage diagnostics.
/// </summary>
public enum AshlarSchemaStatus
{
    /// <summary>
    /// The provider schema is current.
    /// </summary>
    Current = 0,

    /// <summary>
    /// The provider schema has not been initialized.
    /// </summary>
    NotInitialized = 1,

    /// <summary>
    /// The provider schema has pending migrations.
    /// </summary>
    PendingMigrations = 2,

    /// <summary>
    /// The provider schema status could not be determined.
    /// </summary>
    Unknown = 3
}
