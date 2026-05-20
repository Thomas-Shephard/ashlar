namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Represents the authentication context data model.
/// </summary>
/// <param name="Email">The email value.</param>
/// <param name="TenantId">The tenant id value.</param>
/// <param name="IpAddress">The ip address value.</param>
/// <param name="UserAgent">The user agent value.</param>
/// <param name="CorrelationId">The correlation id value.</param>
/// <param name="ReturnUrl">The return url value.</param>
/// <param name="Items">The items value.</param>
/// <param name="UserId">The user id value.</param>
public sealed record AuthenticationContext(
    string? Email = null,
    Guid? TenantId = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? CorrelationId = null,
    string? ReturnUrl = null,
    IReadOnlyDictionary<string, string>? Items = null,
    Guid? UserId = null);
