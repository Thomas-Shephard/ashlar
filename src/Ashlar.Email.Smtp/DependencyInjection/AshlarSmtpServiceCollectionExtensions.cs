using Ashlar.Email.Smtp;
using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection.Extensions;

// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Extension methods for registering Ashlar SMTP email services.
/// </summary>
public static class AshlarSmtpServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Ashlar SMTP email transport.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="configure">The configuration action.</param>
    /// <returns>The <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAshlarSmtpEmailTransport(
        this IServiceCollection services,
        Action<SmtpEmailOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.TryAddTransient<IEmailTransport, SmtpEmailTransport>();

        return services;
    }

    /// <summary>
    /// Registers the Ashlar SMTP email transport and sets it as the primary <see cref="IEmailSender"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="configure">The configuration action.</param>
    /// <returns>The <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddAshlarSmtpEmailSender(
        this IServiceCollection services,
        Action<SmtpEmailOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddAshlarSmtpEmailTransport(configure);
        services.Replace(ServiceDescriptor.Transient<IEmailSender, SmtpEmailSender>());

        return services;
    }
}
