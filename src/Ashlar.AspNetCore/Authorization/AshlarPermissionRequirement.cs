using Microsoft.AspNetCore.Authorization;

namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// An ASP.NET Core authorization requirement that checks for a specific Ashlar permission.
/// </summary>
public sealed class AshlarPermissionRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AshlarPermissionRequirement"/> class.
    /// </summary>
    /// <param name="permission">The permission value.</param>
    /// <param name="policyName">The policy name value.</param>
    public AshlarPermissionRequirement(string permission, string policyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        Permission = permission.ToLowerInvariant();
        PolicyName = policyName;
    }

    /// <summary>
    /// Gets the normalized permission name.
    /// </summary>
    public string Permission { get; }

    /// <summary>
    /// Gets the name of the policy this requirement belongs to.
    /// </summary>
    public string PolicyName { get; }
}


