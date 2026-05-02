namespace Ashlar.Identity.Models;

/// <summary>
/// Describes the outcome of authentication session validation.
/// </summary>
public enum AuthenticationSessionValidationStatus
{
    Failed = 0,
    Success = 1,
    Expired = 2,
    Revoked = 3
}
