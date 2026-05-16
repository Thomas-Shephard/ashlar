namespace Ashlar.Identity.Models;

/// <summary>
/// Provides create invitation request behavior.
/// </summary>
public sealed class CreateInvitationRequest
{
    /// <summary>
    /// Gets or sets the email value.
    /// </summary>
    public required string Email { get; init; }
    /// <summary>
    /// Gets or sets the tenant id value.
    /// </summary>
    public Guid? TenantId { get; init; }
    /// <summary>
    /// Gets or sets the expiry value.
    /// </summary>
    public TimeSpan? Expiry { get; init; }
    /// <summary>
    /// Gets or sets the metadata value.
    /// </summary>
    public string? Metadata { get; init; }
}
