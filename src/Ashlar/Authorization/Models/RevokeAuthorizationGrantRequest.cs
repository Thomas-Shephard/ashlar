namespace Ashlar.Authorization.Models;

/// <summary>
/// Represents the revoke authorization grant request data model.
/// </summary>
/// <param name="GrantId">The grant id value.</param>
public sealed record RevokeAuthorizationGrantRequest(Guid GrantId);
