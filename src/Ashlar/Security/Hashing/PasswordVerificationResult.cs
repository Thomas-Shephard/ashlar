namespace Ashlar.Security.Hashing;

/// <summary>
/// Defines the available password verification result values.
/// </summary>
public enum PasswordVerificationResult
{
    /// <summary>
    /// Represents the failed value.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Represents the success value.
    /// </summary>
    Success = 1,
    /// <summary>
    /// Represents the success with credential update value.
    /// </summary>
    SuccessWithCredentialUpdate = 2
}
