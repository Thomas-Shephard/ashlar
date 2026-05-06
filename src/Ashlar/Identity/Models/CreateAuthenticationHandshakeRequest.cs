namespace Ashlar.Identity.Models;

public sealed record CreateAuthenticationHandshakeRequest(
    Guid UserId,
    IEnumerable<string> RequiredFactors,
    IDictionary<string, string>? Metadata = null);
