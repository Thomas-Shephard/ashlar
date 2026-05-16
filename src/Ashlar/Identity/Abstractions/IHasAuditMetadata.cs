namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Defines common audit metadata for identity entities.
/// </summary>
public interface IHasAuditMetadata
{
    /// <summary>
    /// Gets the created at value.
    /// </summary>
    DateTimeOffset CreatedAt { get; }
    /// <summary>
    /// Gets the updated at value.
    /// </summary>
    DateTimeOffset? UpdatedAt { get; set; }
}
