namespace Ashlar.Identity.Abstractions.Tenancy;

/// <summary>
/// Defines common audit metadata for identity entities.
/// </summary>
public interface IHasAuditMetadata
{
    /// <summary>
    /// Gets the UTC time when the entity was created.
    /// </summary>
    DateTimeOffset CreatedAt { get; }
    /// <summary>
    /// UTC time when the entity was last updated, when tracked.
    /// </summary>
    DateTimeOffset? UpdatedAt { get; set; }
}
