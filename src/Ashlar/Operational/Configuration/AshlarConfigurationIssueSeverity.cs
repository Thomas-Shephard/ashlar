namespace Ashlar.Operational.Configuration;

/// <summary>
/// Describes the severity of an Ashlar configuration validation issue.
/// </summary>
public enum AshlarConfigurationIssueSeverity
{
    /// <summary>
    /// Informational configuration detail.
    /// </summary>
    Information = 0,

    /// <summary>
    /// Configuration that may be acceptable in development but should be reviewed for production.
    /// </summary>
    Warning = 1,

    /// <summary>
    /// Configuration that is incomplete or unsafe for normal Ashlar identity use.
    /// </summary>
    Error = 2,
}
