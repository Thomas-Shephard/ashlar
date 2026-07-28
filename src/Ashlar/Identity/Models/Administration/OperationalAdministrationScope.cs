namespace Ashlar.Identity.Models.Administration;

/// <summary>Explicit scope for administration of global, unpartitioned operational state.</summary>
public enum OperationalAdministrationScope
{
    /// <summary>No operational scope was supplied.</summary>
    Unspecified = 0,

    /// <summary>The global operational store across all tenant origins.</summary>
    Global = 1
}
