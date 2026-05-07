namespace Ashlar.Identity.Models;

public sealed record AuthenticationContext(
    string? Email = null,
    Guid? TenantId = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? CorrelationId = null,
    string? ReturnUrl = null,
    IReadOnlyDictionary<string, string>? Items = null,
    Guid? UserId = null);
