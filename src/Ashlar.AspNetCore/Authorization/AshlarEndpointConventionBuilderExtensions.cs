// ReSharper disable CheckNamespace

using Ashlar.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;

#pragma warning disable IDE0130
namespace Microsoft.AspNetCore.Routing;
#pragma warning restore IDE0130

/// <summary>
/// Provides endpoint convention helpers for Ashlar authorization policies.
/// </summary>
public static class AshlarEndpointConventionBuilderExtensions
{
    /// <summary>
    /// Requires the default Ashlar fresh MFA policy.
    /// </summary>
    /// <typeparam name="TBuilder">The endpoint convention builder type.</typeparam>
    /// <param name="builder">The endpoint convention builder.</param>
    /// <returns>The endpoint convention builder.</returns>
    public static TBuilder RequireFreshMfa<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.RequireAuthorization(AshlarStepUpPolicyNames.FreshMfa);
    }

    /// <summary>
    /// Requires the default Ashlar conditional fresh MFA policy.
    /// </summary>
    /// <typeparam name="TBuilder">The endpoint convention builder type.</typeparam>
    /// <param name="builder">The endpoint convention builder.</param>
    /// <returns>The endpoint convention builder.</returns>
    public static TBuilder RequireFreshMfaIfAvailable<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.RequireAuthorization(AshlarStepUpPolicyNames.FreshMfaIfAvailable);
    }
}


