namespace Ashlar.Identity.Models;

public sealed class BootstrapOptions
{
    public List<BootstrapGrantTemplate> Grants { get; set; } = [];
}

public sealed class BootstrapGrantTemplate
{
    public string? Role { get; set; }
    public string? Permission { get; set; }
    public string? ScopeType { get; set; }
    public string? ScopeId { get; set; }
    public Guid? TenantId { get; set; }
}
