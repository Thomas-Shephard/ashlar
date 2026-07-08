namespace Ashlar.Identity.Models.Bootstrap;

/// <summary>
/// Successful first-admin bootstrap result.
/// </summary>
/// <param name="UserId">The administrator user created or activated by bootstrap.</param>
/// <param name="AuthenticationResult">Ashlar-issued authentication completion result required before creating a session for the bootstrapped administrator.</param>
public sealed record BootstrapFirstAdminResult(Guid UserId, MfaAuthenticationResult AuthenticationResult);
