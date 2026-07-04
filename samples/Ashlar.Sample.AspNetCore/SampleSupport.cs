using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Ashlar.Messaging;
using Dapper;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Ashlar.Sample.AspNetCore;

internal sealed record BootstrapFirstAdminEndpointRequest(string? Email, string? UserName, string? SetupSecret)
{
    public static async Task<BootstrapFirstAdminEndpointRequest?> ReadAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.ContentLength is 0)
        {
            return null;
        }

        if (!request.HasJsonContentType())
        {
            return null;
        }

        try
        {
            return await JsonSerializer.DeserializeAsync<BootstrapFirstAdminEndpointRequest>(
                request.Body,
                JsonSerializerOptions.Web,
                cancellationToken);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

internal sealed record MagicLinkRequest(string Email);
internal sealed record MagicLinkCallbackRequest(string T);
internal sealed record TotpVerifyRequest(string SharedSecret, string Code);
internal sealed record MfaVerifyRequest(string HandshakeToken, string Code);
internal sealed record ProjectGrantRequest(Guid UserId);
internal sealed record EmailCodeRequest(string Email);
internal sealed record EmailCodeVerifyRequest(string Email, string Code);
internal sealed record SampleEmailChangeRequest(string NewEmail);
internal sealed record SampleEmailChangeConfirmRequest(string Token);
internal sealed record SampleEmailVerificationConfirmRequest(string Token);
internal sealed record UpdateProfileRequest(string? Name);

internal static class SampleGoogleOidc
{
    public const string ProviderName = "Google";
    public const string InvitationTokenProperty = "ashlar.sample.invitationToken";
    public const string InvitationDisplayNameProperty = "ashlar.sample.invitationDisplayName";

    public static bool IsConfigured(IConfiguration configuration)
    {
        return !string.IsNullOrWhiteSpace(configuration["Authentication:Google:ClientId"])
            && !string.IsNullOrWhiteSpace(configuration["Authentication:Google:ClientSecret"]);
    }

    public static string[] GetHostedDomains(IConfiguration configuration)
    {
        var section = configuration.GetSection("Authentication:Google:HostedDomains");
        var values = section.Get<string[]>();
        if (values is { Length: > 0 })
        {
            return NormalizeHostedDomains(values);
        }

        var singleValue = configuration["Authentication:Google:HostedDomains"];
        return string.IsNullOrWhiteSpace(singleValue)
            ? []
            : NormalizeHostedDomains(singleValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    private static string[] NormalizeHostedDomains(IEnumerable<string> values)
    {
        return values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

internal static class SampleGitHubOAuth
{
    public const string ProviderName = "GitHub";

    public static bool IsConfigured(IConfiguration configuration)
    {
        return !string.IsNullOrWhiteSpace(configuration["Authentication:GitHub:ClientId"])
            && !string.IsNullOrWhiteSpace(configuration["Authentication:GitHub:ClientSecret"]);
    }
}

internal static class SampleResultErrors
{
    public static object From(Result result, string? fallbackMessage = null)
    {
        var code = result.FailureCode?.Value;
        return new
        {
            code,
            message = result.FailureMessage ?? fallbackMessage ?? code ?? "Operation failed."
        };
    }
}

internal sealed class SampleAshlarOptions
{
    public string ConnectionString { get; init; } = string.Empty;

    [Required]
    public string AppName { get; init; } = "Ashlar Sample";

    [Required]
    public required string PublicAppUrl { get; init; }

    public SampleCookieOptions Cookie { get; init; } = new();
    public SampleOutboxOptions Outbox { get; init; } = new();
    public SampleCleanupOptions Cleanup { get; init; } = new();
}

internal sealed class SampleCookieOptions
{
    public string Name { get; init; } = "Ashlar.Sample";
    public bool Secure { get; init; }
}

internal sealed class SampleOutboxOptions
{
    public TimeSpan PollingInterval { get; init; } = TimeSpan.FromSeconds(1);
    public int BatchSize { get; init; } = 25;
}

internal sealed class SampleCleanupOptions
{
    public TimeSpan CleanupInterval { get; init; } = TimeSpan.FromHours(1);
}

internal static class SampleSchemaInitializer
{
    public static async Task InitializeAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        await using var scope = services.CreateAsyncScope();
        var dataSource = scope.ServiceProvider.GetRequiredService<NpgsqlDataSource>();
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await connection.ExecuteAsync(new CommandDefinition("""
            CREATE TABLE IF NOT EXISTS sample_projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            INSERT INTO sample_projects (id, name)
            VALUES ('alpha', 'Project Alpha'), ('beta', 'Project Beta')
            ON CONFLICT DO NOTHING;
        """, cancellationToken: cancellationToken));
    }
}

internal static class DevelopmentPostgresStartup
{
    public static async Task<DevelopmentPostgresStartupResult> ConfigureAsync(WebApplicationBuilder builder)
    {
        var configuredConnectionString = builder.Configuration["Ashlar:ConnectionString"];
        if (!string.IsNullOrWhiteSpace(configuredConnectionString))
        {
            return new DevelopmentPostgresStartupResult(configuredConnectionString, null);
        }

        var container = new PostgreSqlBuilder("postgres:15-alpine")
            .WithDatabase("ashlar_sample")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await container.StartAsync();

        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Ashlar:ConnectionString"] = container.GetConnectionString()
        });

        return new DevelopmentPostgresStartupResult(container.GetConnectionString(), container);
    }
}

internal sealed record DevelopmentPostgresStartupResult(string ConnectionString, IAsyncDisposable? Container);

internal sealed class DevelopmentEmailTransport(ILogger<DevelopmentEmailTransport> logger) : IEmailTransport
{
    private static readonly Action<ILogger, string, string, Exception?> EmailObserved =
        LoggerMessage.Define<string, string>(
            LogLevel.Information,
            new EventId(1, nameof(EmailObserved)),
            "Development email transport observed a message for {Recipient} with subject {Subject}.");

    private static readonly Action<ILogger, string?, string?, Exception?> EmailBodyObserved =
        LoggerMessage.Define<string?, string?>(
            LogLevel.Warning,
            new EventId(2, nameof(EmailBodyObserved)),
            "Development-only email body. Text: {TextBody} HTML: {HtmlBody}");

    public Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        EmailObserved(logger, message.To, message.Subject, null);
        EmailBodyObserved(logger, message.TextBody, message.HtmlBody, null);
        return Task.CompletedTask;
    }
}

internal static class LandingPages
{
    public static IResult Render(string title, string description, string script)
    {
        return Layout(title, $$"""
            <div class="card">
                <h1>{{title}}</h1>
                <p>{{description}}</p>
                {{script}}
            </div>
            """);
    }

    public static IResult Layout(string title, string content, string? navLinks = null)
    {
        return Results.Content($$"""
            <html>
            <head>
                <title>{{title}} - Ashlar</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; flex-direction: column; align-items: center; min-height: 100vh; margin: 0; background: #f9fafb; color: #111827; }
                    .container { max-width: 800px; width: 100%; padding: 2rem; box-sizing: border-box; }
                    .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); width: 100%; box-sizing: border-box; margin-bottom: 1.5rem; }
                    h1 { color: #111827; margin-top: 0; font-size: 1.5rem; }
                    h2 { color: #374151; font-size: 1.25rem; margin-bottom: 1rem; }
                    h3 { color: #374151; font-size: 1.125rem; margin-top: 1.5rem; margin-bottom: 0.75rem; }
                    p { color: #4b5563; line-height: 1.5; margin-bottom: 1rem; }
                    input { width: 100%; padding: 0.75rem; margin: 0.5rem 0 1rem 0; border: 1px solid #d1d5db; border-radius: 4px; box-sizing: border-box; }
                    button { background: #2563eb; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 4px; font-weight: 600; cursor: pointer; width: 100%; transition: background 0.2s; height: 3rem; }
                    button:hover { background: #1d4ed8; }
                    button:disabled { background: #9ca3af; cursor: not-allowed; }
                    button.secondary { background: #f3f4f6; color: #374151; border: 1px solid #d1d5db; }
                    button.secondary:hover { background: #e5e7eb; }
                    button.danger { color: #dc2626; border-color: #fca5a5; }
                    button.danger:hover { background: #fef2f2; }
                    button.google-button { background: #fff; color: #1f1f1f; border: 1px solid #747775; height: 3rem; width: 100%; display: inline-flex; justify-content: center; align-items: center; gap: 10px; font-family: Roboto, Arial, sans-serif; font-size: 0.875rem; font-weight: 500; line-height: 1.25rem; padding: 0 12px; }
                    button.google-button:hover { background: #f8fafd; box-shadow: none; }
                    button.google-button img { display: block; width: 18px; height: 18px; object-fit: contain; background: #fff; flex: 0 0 18px; }
                    button.github-button { background: #24292f; color: #fff; border: 1px solid #24292f; height: 3rem; width: 100%; display: inline-flex; justify-content: center; align-items: center; gap: 10px; font-size: 0.875rem; font-weight: 600; line-height: 1.25rem; padding: 0 12px; }
                    button.github-button:hover { background: #32383f; box-shadow: none; }
                    button.github-button img { display: block; width: 18px; height: 18px; object-fit: contain; flex: 0 0 18px; }
                    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
                    form { margin: 0; }
                    .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; background: #e5e7eb; color: #374151; }
                    .badge-success { background: #dcfce7; color: #166534; }
                    .badge-warning { background: #fef9c3; color: #854d0e; }
                    .sign-in-button-wrap { position: relative; }
                    .last-sign-in-pill { position: absolute; right: 0.75rem; top: -0.65rem; z-index: 1; white-space: nowrap; box-shadow: 0 1px 2px rgb(0 0 0 / 0.08); }
                    .status-box { background: #f3f4f6; padding: 1rem; border-radius: 4px; margin-bottom: 1.5rem; font-size: 0.875rem; }
                    #result { margin-top: 1rem; font-weight: 500; font-size: 0.875rem; min-height: 1.25rem; }
                    code { background: #f3f4f6; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.875rem; word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
                    .nav { margin-bottom: 2rem; width: 100%; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e5e7eb; padding-bottom: 1rem; }
                    .nav-brand { font-weight: 800; font-size: 1.5rem; color: #2563eb; text-decoration: none; font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; letter-spacing: -0.02em; }
                    .nav-links { display: flex; gap: 1rem; align-items: center; }
                    .nav-links a, .nav-links button.link-btn { color: #4b5563; text-decoration: none; font-size: 0.875rem; font-weight: 500; background: none; border: none; padding: 0; cursor: pointer; font-family: inherit; }
                    .nav-links a:hover, .nav-links button.link-btn:hover { color: #2563eb; }
                    .hidden { display: none; }
                    @media (max-width: 640px) {
                        .nav { flex-direction: column; align-items: flex-start; gap: 1rem; }
                        .nav-links { flex-direction: column; align-items: flex-start; gap: 0.75rem; width: 100%; }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <nav class="nav">
                        <a href="/" class="nav-brand">Ashlar Sample</a>
                        <div class="nav-links">
                            {{navLinks}}
                        </div>
                    </nav>
                    {{content}}
                </div>
            </body>
            </html>
            """, "text/html");
    }
}
