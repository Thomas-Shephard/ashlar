using System.Net;
using Microsoft.Extensions.Options;

namespace Ashlar.Sample.AspNetCore;

internal static class SampleDevelopmentSafetyWarnings
{
    private const string NotApplicable = "n/a";

    private static readonly Action<ILogger, string, string, string, Exception?> DevelopmentOnlySetting =
        LoggerMessage.Define<string, string, string>(
            LogLevel.Warning,
            new EventId(10, nameof(DevelopmentOnlySetting)),
            "Ashlar sample is running with development-only setting {Setting}. Scheme: {Scheme}. Host classification: {HostClassification}. This is for local development only and must not be copied into production.");

    internal static void LogStartupWarnings(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<SampleAshlarOptions>>().Value;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("Ashlar.Sample.AspNetCore.DevelopmentSafety");
        LogStartupWarnings(options, logger);
    }

    private static void LogStartupWarnings(SampleAshlarOptions options, ILogger logger)
    {
        foreach (var warning in Analyze(options))
        {
            DevelopmentOnlySetting(logger, warning.Setting, warning.Scheme, warning.HostClassificationValue, null);
        }
    }

    private static List<DevelopmentSafetyWarning> Analyze(SampleAshlarOptions options)
    {
        var publicAppUri = new Uri(options.PublicAppUrl, UriKind.Absolute);
        var hostClassification = ClassifyHost(publicAppUri.Host);
        var warnings = new List<DevelopmentSafetyWarning>();

        if (publicAppUri.Scheme == Uri.UriSchemeHttp)
        {
            warnings.Add(new DevelopmentSafetyWarning("Ashlar:PublicAppUrl uses HTTP", publicAppUri.Scheme, hostClassification));
        }

        if (hostClassification != HostClassification.Public)
        {
            warnings.Add(new DevelopmentSafetyWarning(
                "Ashlar:PublicAppUrl uses localhost or loopback host",
                publicAppUri.Scheme,
                hostClassification));
        }

        if (!options.Cookie.Secure)
        {
            warnings.Add(new DevelopmentSafetyWarning("Ashlar:Cookie:Secure is false", NotApplicable, NotApplicable));
        }

        warnings.Add(new DevelopmentSafetyWarning("DevelopmentEmailTransport logs email bodies", NotApplicable, NotApplicable));

        return warnings;
    }

    private static string ClassifyHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return HostClassification.Localhost;
        }

        if (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address))
        {
            return HostClassification.Loopback;
        }

        return HostClassification.Public;
    }

    private static class HostClassification
    {
        public const string Localhost = "localhost";
        public const string Loopback = "loopback";
        public const string Public = "public";
    }

    private sealed record DevelopmentSafetyWarning(string Setting, string Scheme, string HostClassificationValue);
}
