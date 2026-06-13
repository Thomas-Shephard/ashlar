namespace Ashlar.Auditing;

/// <summary>
/// Defines provider-neutral outcome values for security events.
/// </summary>
public static class SecurityEventOutcomes
{
    /// <summary>
    /// The security-sensitive operation succeeded.
    /// </summary>
    public const string Success = "success";
    /// <summary>
    /// The security-sensitive operation failed.
    /// </summary>
    public const string Failure = "failure";
}
