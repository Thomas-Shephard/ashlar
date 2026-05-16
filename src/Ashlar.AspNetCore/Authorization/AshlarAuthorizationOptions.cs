using Microsoft.AspNetCore.Authorization;

namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// Options for configuring Ashlar ASP.NET Core authorization.
/// </summary>
public sealed class AshlarAuthorizationOptions
{
    private readonly Dictionary<string, AshlarScopeOptions> _policyScopes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the registered policy scope options.
    /// </summary>
    public IReadOnlyDictionary<string, AshlarScopeOptions> PolicyScopes => _policyScopes;

    /// <summary>
    /// Adds a policy that requires a specific Ashlar permission.
    /// </summary>
    /// <param name="policyName">The policy name value.</param>
    /// <param name="permission">The permission value.</param>
    /// <param name="configureScope">The configure scope value.</param>
    public void AddPermissionPolicy(string policyName, string permission, Action<AshlarScopeOptions>? configureScope = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        var requirement = new AshlarPermissionRequirement(permission, policyName);
        ConfigurePolicy(policyName, requirement, configureScope);
    }

    /// <summary>
    /// Adds a policy that requires a specific Ashlar role.
    /// </summary>
    /// <param name="policyName">The policy name value.</param>
    /// <param name="role">The role value.</param>
    /// <param name="configureScope">The configure scope value.</param>
    public void AddRolePolicy(string policyName, string role, Action<AshlarScopeOptions>? configureScope = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        ArgumentException.ThrowIfNullOrWhiteSpace(role);

        var requirement = new AshlarRoleRequirement(role, policyName);
        ConfigurePolicy(policyName, requirement, configureScope);
    }

    internal List<(string Name, AuthorizationPolicy Policy)> Policies { get; } = [];

    private void ConfigurePolicy(string policyName, IAuthorizationRequirement requirement, Action<AshlarScopeOptions>? configureScope)
    {
        var builder = new AuthorizationPolicyBuilder();
        builder.AddRequirements(requirement);
        builder.RequireAuthenticatedUser();

        Policies.Add((policyName, builder.Build()));

        if (configureScope != null)
        {
            var scopeOptions = new AshlarScopeOptions();
            configureScope(scopeOptions);
            _policyScopes[policyName] = scopeOptions;
        }
    }

    internal void AddPolicyScope(string policyName, AshlarScopeOptions scopeOptions)
    {
        _policyScopes[policyName] = scopeOptions;
    }
}
