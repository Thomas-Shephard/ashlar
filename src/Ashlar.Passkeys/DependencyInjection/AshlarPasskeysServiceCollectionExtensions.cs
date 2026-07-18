using Ashlar.Passkeys;
using Microsoft.Extensions.DependencyInjection.Extensions;

// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides dependency injection registration helpers for Ashlar passkey services.
/// </summary>
public static class AshlarPasskeysServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar passkey authentication services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The passkey options configuration callback.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// This registration includes MFA orchestration because passkeys can be used as MFA factors. It makes passkey factors
    /// available, but applications must register an explicit MFA policy such as <c>AddAshlarNoMfaPolicy</c>,
    /// <c>AddAshlarRequireMfaForAllUsers</c>, <c>AddAshlarRequireMfaWhenCredentialExists</c>, or a custom
    /// <c>IMfaPolicyEvaluator</c> before resolving the authentication orchestrator. Applications must also provide the
    /// normal Ashlar identity, credential, passkey challenge, and authentication handshake persistence services, for example via
    /// <c>AddAshlarPostgres</c>.
    /// </remarks>
    public static IServiceCollection AddAshlarPasskeys(this IServiceCollection services, Action<PasskeyOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarPasskeyCore();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped<IPasskeyCeremonyValidator, Fido2PasskeyCeremonyValidator>();
        return services;
    }
}
