using Microsoft.AspNetCore.Authorization;

namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// An ASP.NET Core authorization requirement that checks for a specific Ashlar role.
/// </summary>
public sealed class AshlarRoleRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AshlarRoleRequirement"/> class.
    /// </summary>
    /// <param name="role">The role value.</param>
    /// <param name="policyName">The policy name value.</param>
    public AshlarRoleRequirement(string role, string policyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        Role = role.ToLowerInvariant();
        PolicyName = policyName;
    }

    /// <summary>
    /// Gets the normalized role name.
    /// </summary>
    public string Role { get; }

    /// <summary>
    /// Gets the name of the policy this requirement belongs to.
    /// </summary>
    public string PolicyName { get; }
}
