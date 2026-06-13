namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Describes the outcome of authentication session validation.
/// </summary>
public enum AuthenticationSessionValidationStatus
{
    /// <summary>
    /// Represents the failed value.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Represents the succeeded value.
    /// </summary>
    Succeeded = 1,
    /// <summary>
    /// Represents the expired value.
    /// </summary>
    Expired = 2,
    /// <summary>
    /// Represents the revoked value.
    /// </summary>
    Revoked = 3
}
