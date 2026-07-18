namespace Ashlar.OAuth;

/// <summary>
/// Contains safe, display-oriented profile hints read from a validated OpenID Connect principal.
/// </summary>
/// <param name="DisplayName">The suggested display name, when one is available.</param>
/// <param name="GivenName">The given name, when one is available.</param>
/// <param name="FamilyName">The family name, when one is available.</param>
/// <param name="Email">The mail address, when one is available.</param>
/// <param name="EmailVerified">The parsed standard verification hint, when recognized.</param>
public sealed record AshlarOidcProfile(
    string? DisplayName,
    string? GivenName,
    string? FamilyName,
    string? Email,
    bool? EmailVerified);
