namespace Ashlar.Security.Hashing;

/// <summary>
/// Lists password hash verification outcomes.
/// </summary>
public enum PasswordVerificationResult
{
    /// <summary>
    /// The password did not match the stored hash.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// The password matched and the stored hash uses the current format.
    /// </summary>
    Success = 1,
    /// <summary>
    /// The password matched, but the credential should be rehashed with the current format.
    /// </summary>
    SuccessWithCredentialUpdate = 2
}
