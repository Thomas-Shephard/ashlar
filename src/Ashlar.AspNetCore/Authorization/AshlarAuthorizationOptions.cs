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
    /// Gets the default step-up policy options.
    /// </summary>
    public AshlarStepUpOptions StepUp { get; } = new();

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

    /// <summary>
    /// Adds a policy that requires fresh Ashlar additional verification.
    /// </summary>
    /// <param name="policyName">The policy name value.</param>
    /// <param name="configure">The optional step-up options callback.</param>
    public void AddAshlarStepUpPolicy(string policyName, Action<AshlarStepUpOptions>? configure = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        var stepUpOptions = CopyStepUpOptions(StepUp);
        configure?.Invoke(stepUpOptions);

        var requirement = new AshlarStepUpRequirement(
            stepUpOptions.FreshnessWindow,
            stepUpOptions.AllowedProviders,
            stepUpOptions.AllowedFactors);

        ConfigurePolicy(policyName, requirement, null);
    }

    /// <summary>
    /// Adds a policy that requires fresh Ashlar additional verification when an eligible factor is available.
    /// </summary>
    /// <param name="policyName">The policy name value.</param>
    /// <param name="configure">The optional step-up options callback.</param>
    public void AddAshlarStepUpIfAvailablePolicy(string policyName, Action<AshlarStepUpOptions>? configure = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        var stepUpOptions = CopyStepUpOptions(StepUp);
        if (stepUpOptions.AllowedFactors.Count == 0)
        {
            stepUpOptions.AllowedFactors.Add(AuthenticationFactorTypes.Totp);
            stepUpOptions.AllowedFactors.Add(AuthenticationFactorTypes.RecoveryCode);
            stepUpOptions.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);
        }

        configure?.Invoke(stepUpOptions);

        var requirement = new AshlarStepUpRequirement(
            stepUpOptions.FreshnessWindow,
            stepUpOptions.AllowedProviders,
            stepUpOptions.AllowedFactors,
            AshlarStepUpMode.IfAvailable);

        ConfigurePolicy(policyName, requirement, null);
    }

    /// <summary>
    /// Adds the default fresh MFA policy.
    /// </summary>
    /// <param name="configure">The optional step-up options callback.</param>
    public void RequireFreshMfa(Action<AshlarStepUpOptions>? configure = null)
    {
        AddAshlarStepUpPolicy(AshlarStepUpPolicyNames.FreshMfa, configure);
    }

    /// <summary>
    /// Adds the default conditional fresh MFA policy.
    /// </summary>
    /// <param name="configure">The optional step-up options callback.</param>
    public void RequireFreshMfaIfAvailable(Action<AshlarStepUpOptions>? configure = null)
    {
        AddAshlarStepUpIfAvailablePolicy(AshlarStepUpPolicyNames.FreshMfaIfAvailable, configure);
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

    private static AshlarStepUpOptions CopyStepUpOptions(AshlarStepUpOptions source)
    {
        var copy = new AshlarStepUpOptions { FreshnessWindow = source.FreshnessWindow };
        foreach (var provider in source.AllowedProviders)
        {
            copy.AllowedProviders.Add(provider);
        }

        foreach (var factor in source.AllowedFactors)
        {
            copy.AllowedFactors.Add(factor);
        }

        return copy;
    }
}
