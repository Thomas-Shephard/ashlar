namespace Ashlar.Identity.Models.Credentials;

/// <summary>
/// Lists credential lifecycle states used by authentication and administration APIs.
/// </summary>
public enum CredentialStatus
{
    /// <summary>
    /// The credential can be used for authentication.
    /// </summary>
    Active = 0,
    /// <summary>
    /// The credential has been revoked and must not authenticate future requests.
    /// </summary>
    Revoked = 1
}
