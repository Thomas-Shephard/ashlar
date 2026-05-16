// ReSharper disable CheckNamespace

using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Authorization;
using Ashlar.AspNetCore.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;

#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides dependency injection registration helpers for Ashlar ASP.NET Core session authentication.
/// </summary>
public static class AshlarAspNetCoreServiceCollectionExtensions
{
    /// <summary>
    /// Adds Ashlar ASP.NET Core session authentication services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">The optional session authentication options callback.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddAshlarAspNetCoreSessions(
        this IServiceCollection services,
        Action<AshlarSessionAuthenticationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var configuredOptions = new AshlarSessionAuthenticationOptions();
        configure?.Invoke(configuredOptions);
        ValidateOptions(configuredOptions);

        services.AddHttpContextAccessor();
        services.TryAddSingleton(new AshlarSessionRegistration { SchemeName = configuredOptions.SchemeName });
        services.TryAddScoped<IAshlarSignInManager, AshlarSignInManager>();

        var authenticationBuilder = services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme ??= configuredOptions.SchemeName;
            options.DefaultChallengeScheme ??= configuredOptions.SchemeName;
            options.DefaultForbidScheme ??= configuredOptions.SchemeName;
        });

        authenticationBuilder.AddScheme<AshlarSessionAuthenticationOptions, AshlarSessionAuthenticationHandler>(
            configuredOptions.SchemeName,
            options =>
            {
                CopyOptions(configuredOptions, options);
                ValidateOptions(options);
            });

        return services;
    }

    /// <summary>
    /// Adds Ashlar ASP.NET Core authorization integration.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarAspNetCoreAuthorization(
        this IServiceCollection services,
        Action<AshlarAuthorizationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new AshlarAuthorizationOptions();
        configure?.Invoke(options);

        services.Configure<AshlarAuthorizationOptions>(opt =>
        {
            foreach (var (name, scope) in options.PolicyScopes)
            {
                opt.AddPolicyScope(name, scope);
            }
        });

        services.AddAuthorization(authOptions =>
        {
            foreach (var (name, policy) in options.Policies)
            {
                authOptions.AddPolicy(name, policy);
            }
        });

        services.AddHttpContextAccessor();
        services.TryAddEnumerable(ServiceDescriptor.Transient<IAuthorizationHandler, AshlarAuthorizationHandler>());

        return services;
    }

    private static void CopyOptions(AshlarSessionAuthenticationOptions source, AshlarSessionAuthenticationOptions destination)
    {
        destination.SchemeName = source.SchemeName;
        destination.CookieName = source.CookieName;
        destination.ClaimsIssuer = source.ClaimsIssuer;
        destination.SlidingCookieExpiration = source.SlidingCookieExpiration;
        destination.LoginPath = source.LoginPath;
        destination.AccessDeniedPath = source.AccessDeniedPath;
        destination.Cookie.HttpOnly = source.Cookie.HttpOnly;
        destination.Cookie.SecurePolicy = source.Cookie.SecurePolicy;
        destination.Cookie.SameSite = source.Cookie.SameSite;
        destination.Cookie.Path = source.Cookie.Path;
        destination.Cookie.Domain = source.Cookie.Domain;
        destination.Cookie.IsEssential = source.Cookie.IsEssential;
        destination.Cookie.MaxAge = source.Cookie.MaxAge;
    }

    private static void ValidateOptions(AshlarSessionAuthenticationOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.SchemeName);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.CookieName);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ClaimsIssuer);

        if (!options.CookieName.StartsWith("__Host-", StringComparison.Ordinal))
        {
            return;
        }

        if (!string.IsNullOrEmpty(options.Cookie.Domain))
        {
            throw new ArgumentException("__Host- cookies must not set Cookie.Domain.", nameof(options));
        }

        if (!string.Equals(options.Cookie.Path, "/", StringComparison.Ordinal))
        {
            throw new ArgumentException("__Host- cookies must set Cookie.Path to '/'.", nameof(options));
        }

        if (options.Cookie.SecurePolicy != CookieSecurePolicy.Always)
        {
            throw new ArgumentException("__Host- cookies must set Cookie.SecurePolicy to Always.", nameof(options));
        }
    }
}
