using System.Collections.Concurrent;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Tests.Smoke;

[NonParallelizable]
internal sealed class SampleDevelopmentSafetyWarningsTests : PostgresTestBase
{
    [Test]
    public void StartupReportsHttpPublicUrlAsDevelopmentOnly()
    {
        using var factory = CreateFactory("http://example.test", cookieSecure: true, out var logs);

        Assert.Throws<OptionsValidationException>(() => _ = factory.CreateClient());

        Assert.That(logs.Settings, Does.Contain("Ashlar:PublicAppUrl uses HTTP"));
    }

    [TestCase("https://localhost")]
    [TestCase("https://127.0.0.1")]
    public void StartupReportsLocalhostOrLoopbackPublicUrlAsDevelopmentOnly(string publicAppUrl)
    {
        using var factory = CreateFactory(publicAppUrl, cookieSecure: true, out var logs);

        _ = factory.CreateClient();

        Assert.That(logs.Settings, Does.Contain("Ashlar:PublicAppUrl uses localhost or loopback host"));
    }

    [Test]
    public void StartupReportsNonSecureCookieSettingsAsDevelopmentOnly()
    {
        using var factory = CreateFactory("https://example.test", cookieSecure: false, out var logs);

        _ = factory.CreateClient();

        Assert.That(logs.Settings, Does.Contain("Ashlar:Cookie:Secure is false"));
    }

    [Test]
    public void StartupWarningsDoNotIncludeSensitiveConfigurationOrRawUrlDetails()
    {
        using var factory = CreateFactory("http://localhost:5000", cookieSecure: false, out var logs);

        _ = factory.CreateClient();

        var output = string.Join(Environment.NewLine, logs.Messages);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(output, Does.Not.Contain("sample-bootstrap-secret"));
            Assert.That(output, Does.Not.Contain("Password="));
            Assert.That(output, Does.Not.Contain("localhost:5000"));
            Assert.That(output, Does.Contain("local development only"));
            Assert.That(logs.WarningCount, Is.GreaterThanOrEqualTo(1));
        }
    }

    [Test]
    public void StartupDoesNotReportHttpLocalhostOrCookieWarningsForSecurePublicConfiguration()
    {
        using var factory = CreateFactory("https://example.test", cookieSecure: true, out var logs);

        _ = factory.CreateClient();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(logs.Settings, Does.Not.Contain("Ashlar:PublicAppUrl uses HTTP"));
            Assert.That(logs.Settings, Does.Not.Contain("Ashlar:PublicAppUrl uses localhost or loopback host"));
            Assert.That(logs.Settings, Does.Not.Contain("Ashlar:Cookie:Secure is false"));
            Assert.That(logs.Settings, Does.Contain("DevelopmentEmailTransport logs email bodies"));
        }
    }

    [Test]
    public void StartupTreatsNonLoopbackIpAddressAsPublicHost()
    {
        using var factory = CreateFactory("https://198.51.100.10", cookieSecure: true, out var logs);

        _ = factory.CreateClient();

        Assert.That(logs.Settings, Does.Not.Contain("Ashlar:PublicAppUrl uses localhost or loopback host"));
    }

    private SampleApplicationFactory CreateFactory(string publicAppUrl, bool cookieSecure, out DevelopmentSafetyLogSink logs)
    {
        logs = new DevelopmentSafetyLogSink();
        return new SampleApplicationFactory(GetConnectionString(), publicAppUrl, cookieSecure, logs);
    }

    private sealed class SampleApplicationFactory : WebApplicationFactory<Program>
    {
        private readonly DevelopmentSafetyLogSink _logs;
        private readonly Dictionary<string, string?> _previousEnvironmentValues = new(StringComparer.Ordinal);

        public SampleApplicationFactory(
            string connectionString,
            string publicAppUrl,
            bool cookieSecure,
            DevelopmentSafetyLogSink logs)
        {
            _logs = logs;

            SetSampleEnvironment("Ashlar__ConnectionString", connectionString);
            SetSampleEnvironment("Ashlar__PublicAppUrl", publicAppUrl);
            SetSampleEnvironment("Ashlar__Bootstrap__SetupSecret", "sample-bootstrap-secret");
            SetSampleEnvironment("Ashlar__Cookie__Secure", cookieSecure.ToString());
            SetSampleEnvironment("Ashlar__Outbox__PollingInterval", "01:00:00");
            SetSampleEnvironment("Ashlar__Cleanup__CleanupInterval", "01:00:00");
            SetSampleEnvironment("Authentication__Google__ClientId", string.Empty);
            SetSampleEnvironment("Authentication__Google__ClientSecret", string.Empty);
            SetSampleEnvironment("Authentication__Google__HostedDomains__0", string.Empty);
            SetSampleEnvironment("Authentication__GitHub__ClientId", string.Empty);
            SetSampleEnvironment("Authentication__GitHub__ClientSecret", string.Empty);
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureLogging(logging => logging.AddProvider(new DevelopmentSafetyLoggerProvider(_logs)));
            builder.ConfigureServices(services =>
            {
                var hostedServices = services
                    .Where(d => d is
                    {
                        ServiceType: var serviceType,
                        ImplementationType: var implementationType
                    } &&
                    serviceType == typeof(IHostedService) &&
                    (implementationType == typeof(PostgresEmailOutboxHostedService) ||
                     implementationType == typeof(PostgresAshlarCleanupHostedService)))
                    .ToList();

                foreach (var hostedService in hostedServices)
                {
                    services.Remove(hostedService);
                }
            });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            RestoreSampleEnvironment();
        }

        private void SetSampleEnvironment(string name, string? value)
        {
            _previousEnvironmentValues.TryAdd(name, Environment.GetEnvironmentVariable(name));
            Environment.SetEnvironmentVariable(name, value);
        }

        private void RestoreSampleEnvironment()
        {
            foreach (var (name, value) in _previousEnvironmentValues)
            {
                Environment.SetEnvironmentVariable(name, value);
            }

            _previousEnvironmentValues.Clear();
        }
    }

    private sealed class DevelopmentSafetyLoggerProvider(DevelopmentSafetyLogSink logs) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName)
        {
            return new DevelopmentSafetyLogger(categoryName, logs);
        }

        public void Dispose()
        {
        }
    }

    private sealed class DevelopmentSafetyLogger(string categoryName, DevelopmentSafetyLogSink logs) : ILogger
    {
        public IDisposable BeginScope<TState>(TState state) where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return logLevel >= LogLevel.Warning;
        }

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (categoryName == "Ashlar.Sample.AspNetCore.DevelopmentSafety" && logLevel == LogLevel.Warning)
            {
                var setting = state is IReadOnlyList<KeyValuePair<string, object?>> values
                    ? values.FirstOrDefault(value => value.Key == "Setting").Value?.ToString()
                    : null;

                logs.Add(formatter(state, exception), setting);
            }
        }
    }

    private sealed class DevelopmentSafetyLogSink
    {
        private readonly ConcurrentQueue<string> _messages = new();
        private readonly ConcurrentQueue<string> _settings = new();

        public IReadOnlyCollection<string> Messages => _messages.ToArray();
        public IReadOnlyCollection<string> Settings => _settings.ToArray();
        public int WarningCount => _messages.Count;

        public void Add(string message, string? setting)
        {
            _messages.Enqueue(message);
            if (setting != null)
            {
                _settings.Enqueue(setting);
            }
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();

        public void Dispose()
        {
        }
    }
}
