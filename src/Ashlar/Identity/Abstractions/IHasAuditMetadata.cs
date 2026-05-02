namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Defines common audit metadata for identity entities.
/// </summary>
public interface IHasAuditMetadata
{
    DateTimeOffset CreatedAt { get; }
    DateTimeOffset? UpdatedAt { get; set; }
}
