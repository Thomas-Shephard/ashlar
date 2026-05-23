using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Dapper;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;

namespace Ashlar.Postgres.Tests.Smoke;

internal sealed partial class SampleAspNetCoreSmokeTests : PostgresTestBase
{
    private SampleApplicationFactory? _factory;
    private HttpClient? _adminClient;
    private readonly Dictionary<string, string?> _previousEnvironmentValues = new(StringComparer.Ordinal);

    private HttpClient AdminClient => _adminClient ?? throw new InvalidOperationException("The test client has not been initialized.");

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        SetSampleEnvironment("Ashlar__ConnectionString", GetConnectionString());
        SetSampleEnvironment("Ashlar__PublicAppUrl", "http://localhost");
        SetSampleEnvironment("Ashlar__Cookie__Secure", "false");
        SetSampleEnvironment("Ashlar__Outbox__PollingInterval", "01:00:00");
        SetSampleEnvironment("Ashlar__Cleanup__CleanupInterval", "01:00:00");
        SetSampleEnvironment("Authentication__Google__ClientId", string.Empty);
        SetSampleEnvironment("Authentication__Google__ClientSecret", string.Empty);
        SetSampleEnvironment("Authentication__Google__HostedDomains__0", string.Empty);

        try
        {
            _factory = new SampleApplicationFactory(GetConnectionString());
            _adminClient = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        }
        catch
        {
            RestoreSampleEnvironment();
            throw;
        }
    }

    public override async Task OneTimeTearDown()
    {
        _adminClient?.Dispose();
        if (_factory != null)
        {
            await _factory.DisposeAsync();
        }

        RestoreSampleEnvironment();

        await base.OneTimeTearDown();
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

    [Test]
    public async Task SampleStackSupportsRepresentativeIdentityAuthorizationAndEmailFlows()
    {
        var status = await GetJsonAsync(AdminClient, "/api/bootstrap/status");
        Assert.That(status.RootElement.GetProperty("status").GetString(), Is.EqualTo("Uninitialized"));

        var adminUserId = await BootstrapFirstAdminAsync();
        await AssertGoogleUiHiddenWhenNotConfiguredAsync(AdminClient);
        await AssertAdminPageIncludesAccountSecurityPanelAsync(AdminClient);
        await EnrollTotpAsync(AdminClient);
        await AssertLastAdminCannotBeDisabledAsync(AdminClient, adminUserId);
        await AssertSessionListingAndRevocationAsync(AdminClient);

        await RequestEmailCodeAsync("admin@example.com");
        await MarkEmailUnverifiedAsync("admin@example.com");
        await VerifyEmailAsync(AdminClient, "admin@example.com");

        var invitedUserId = await InviteAndAcceptUserAsync("member@example.com");

        using var memberClient = _factory!.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await SignInWithMagicLinkAsync(memberClient, "member@example.com");
        await AssertForbiddenAsync(memberClient, "/admin");
        await AssertForbiddenAsync(memberClient, "/projects/alpha");
        await AssertStepUpForbiddenPostAsync(memberClient, "/api/account/change-email/request", new { newEmail = "member.changed@example.com" });

        await GrantProjectAccessAsync(invitedUserId, "alpha");
        await AssertAuthenticatedPageAsync(memberClient, "/projects/alpha");

        var sharedSecret = await EnrollTotpAsync(memberClient);
        var recoveryCodes = await GenerateRecoveryCodesAsync(memberClient);

        await ExpireCurrentStepUpAsync(invitedUserId);
        await AssertStepUpForbiddenPostAsync(memberClient, "/api/mfa/recovery-codes", null);
        await StepUpWithRecoveryCodeAsync(memberClient, recoveryCodes[0]);
        recoveryCodes = await GenerateRecoveryCodesAsync(memberClient);

        await ChangeEmailAsync(memberClient, "member@example.com", "member.changed@example.com");
        await SignInWithMagicLinkAsync(memberClient, "member.changed@example.com");

        using var challengedClient = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await CompleteMagicLinkMfaChallengeAsync(challengedClient, "member.changed@example.com", recoveryCodes[0]);
        await AssertAuthenticatedPageAsync(challengedClient, "/account");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sharedSecret, Is.Not.Empty);
            Assert.That(adminUserId, Is.Not.EqualTo(Guid.Empty));
        }
    }

    [Test]
    public async Task SampleGoogleOidcWiringIsConditionalAndFailsSafelyWithoutExternalTicket()
    {
        var missingGoogleSignIn = await AdminClient.GetAsync("/auth/google");
        Assert.That(missingGoogleSignIn.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));

        Environment.SetEnvironmentVariable("Authentication__Google__ClientId", "sample-client-id");
        Environment.SetEnvironmentVariable("Authentication__Google__ClientSecret", "sample-client-secret");
        Environment.SetEnvironmentVariable("Authentication__Google__HostedDomains__0", "example.com");
        try
        {
            await using var googleFactory = new SampleApplicationFactory(GetConnectionString(), maskGoogleConfiguration: false);
            using var client = googleFactory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

            var signIn = await client.GetAsync("/auth/google");
            var signInCallback = await client.GetAsync("/auth/google/callback");
            var invitationPage = await client.GetAsync("/invitations/accept?t=sample-token");
            var invitationHtml = await invitationPage.Content.ReadAsStringAsync();
            var invitationStart = await client.GetAsync("/invitations/accept/google?t=sample-token&userName=Member");
            var invitationCallback = await client.GetAsync("/invitations/accept/google/callback");

            using (Assert.EnterMultipleScope())
            {
                Assert.That(signIn.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
                Assert.That(signIn.Headers.Location?.Host, Does.Contain("google"));
                Assert.That(await signInCallback.Content.ReadAsStringAsync(), Does.Contain("Google Sign-In Failed"));
                Assert.That(invitationHtml, Does.Contain("Sign up with Google"));
                Assert.That(invitationStart.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
                Assert.That(invitationStart.Headers.Location?.Host, Does.Contain("google"));
                Assert.That(await invitationCallback.Content.ReadAsStringAsync(), Does.Contain("Invitation Could Not Be Accepted"));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("Authentication__Google__ClientId", string.Empty);
            Environment.SetEnvironmentVariable("Authentication__Google__ClientSecret", string.Empty);
            Environment.SetEnvironmentVariable("Authentication__Google__HostedDomains__0", string.Empty);
        }
    }

    private async Task<Guid> BootstrapFirstAdminAsync()
    {
        var response = await AdminClient.PostAsJsonAsync("/api/bootstrap/invitations", new { email = "admin@example.com", userName = "Admin" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        return json.RootElement.GetProperty("userId").GetGuid();
    }

    private static async Task AssertSessionListingAndRevocationAsync(HttpClient client)
    {
        var sessions = await GetJsonAsync(client, "/api/sessions");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(sessions.RootElement.GetArrayLength(), Is.EqualTo(1));
            Assert.That(sessions.RootElement[0].GetProperty("isCurrent").GetBoolean(), Is.True);
        }

        var revokeOthers = await client.DeleteAsync("/api/sessions/others");
        Assert.That(revokeOthers.StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
    }

    private async Task RequestEmailCodeAsync(string email)
    {
        var response = await AdminClient.PostAsJsonAsync("/api/auth/email-code/request", new { email });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

        var body = await LatestOutboxBodyAsync(email, "Your sign-in code");
        Assert.That(SixDigitCodeRegex().IsMatch(body), Is.True);
    }

    private async Task<Guid> InviteAndAcceptUserAsync(string email)
    {
        var response = await AdminClient.PostAsJsonAsync("/api/invitations", new { email });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

        var token = ExtractQueryValue(await LatestOutboxBodyAsync(email, "Invitation to join"), "t");

        using var inviteeClient = _factory!.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var accept = await inviteeClient.PostAsJsonAsync("/api/invitations/accept", new { token, userName = "Member" });
        Assert.That(accept.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var json = await JsonDocument.ParseAsync(await accept.Content.ReadAsStreamAsync());
        return json.RootElement.GetProperty("userId").GetGuid();
    }

    private async Task GrantProjectAccessAsync(Guid userId, string projectId)
    {
        var response = await AdminClient.PostAsJsonAsync($"/api/projects/{projectId}/grants", new { userId });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private async Task SignInWithMagicLinkAsync(HttpClient client, string email)
    {
        var requested = await client.PostAsJsonAsync("/api/auth/magic-link/request", new { email });
        Assert.That(requested.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

        var token = ExtractQueryValue(await LatestOutboxBodyAsync(email, "Sign in to our application"), "t");
        var callback = await client.PostAsJsonAsync("/api/auth/magic-link/callback", new { t = token });
        Assert.That(callback.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private async Task VerifyEmailAsync(HttpClient client, string email)
    {
        var request = await client.PostAsync("/api/account/verify-email/request", null);
        Assert.That(request.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

        var body = await LatestOutboxBodyAsync(email, "Verify your email address");
        var token = ExtractQueryValue(body, "t");
        var userId = ExtractQueryValue(body, "u");

        var confirm = await client.PostAsJsonAsync($"/api/account/verify-email/confirm?u={Uri.EscapeDataString(userId)}", new { token });
        Assert.That(confirm.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private async Task MarkEmailUnverifiedAsync(string email)
    {
        await using var connection = new NpgsqlConnection(GetConnectionString());
        var rows = await connection.ExecuteAsync("""
            UPDATE ashlar_users
            SET email_verified_at = NULL
            WHERE lower(email) = lower(@Email)
            """, new { Email = email });

        Assert.That(rows, Is.EqualTo(1));
    }

    private async Task ChangeEmailAsync(HttpClient client, string oldEmail, string newEmail)
    {
        var request = await client.PostAsJsonAsync("/api/account/change-email/request", new { newEmail });
        Assert.That(request.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

        var body = await LatestOutboxBodyAsync(newEmail, "Confirm your new email address");
        var token = ExtractQueryValue(body, "t");
        var userId = ExtractQueryValue(body, "u");

        var confirm = await client.PostAsJsonAsync($"/api/account/change-email/confirm?u={Uri.EscapeDataString(userId)}", new { token });
        Assert.That(confirm.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var oldAddressCodeRequest = await client.PostAsJsonAsync("/api/auth/email-code/request", new { email = oldEmail });
        Assert.That(oldAddressCodeRequest.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));
    }

    private static async Task<string> EnrollTotpAsync(HttpClient client)
    {
        var page = await client.GetAsync("/account/mfa/enroll");
        Assert.That(page.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var html = await page.Content.ReadAsStringAsync();
        var sharedSecret = ExtractSharedSecret(html);
        var code = GenerateTotpCode(sharedSecret);

        var verify = await client.PostAsJsonAsync("/api/mfa/totp/verify", new { sharedSecret, code });
        Assert.That(verify.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        return sharedSecret;
    }

    private static async Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(HttpClient client)
    {
        var response = await client.PostAsync("/api/mfa/recovery-codes", null);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("codes").GetArrayLength(), Is.GreaterThan(0));
        return json.RootElement.GetProperty("codes").EnumerateArray().Select(code => code.GetString()!).ToArray();
    }

    private async Task ExpireCurrentStepUpAsync(Guid userId)
    {
        await using var connection = new NpgsqlConnection(GetConnectionString());
        var rows = await connection.ExecuteAsync("""
            UPDATE ashlar_sessions
            SET additional_verification_at = now() - interval '1 hour'
            WHERE user_id = @UserId
              AND revoked_at IS NULL
            """, new { UserId = userId });

        Assert.That(rows, Is.GreaterThanOrEqualTo(1));
    }

    private static async Task StepUpWithRecoveryCodeAsync(HttpClient client, string recoveryCode)
    {
        var response = await client.PostAsJsonAsync("/api/account/security/verify", new { code = recoveryCode });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
    }

    private async Task CompleteMagicLinkMfaChallengeAsync(HttpClient client, string email, string recoveryCode)
    {
        var requested = await client.PostAsJsonAsync("/api/auth/magic-link/request", new { email });
        Assert.That(requested.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

        var token = ExtractQueryValue(await LatestOutboxBodyAsync(email, "Sign in to our application"), "t");
        var callback = await client.PostAsJsonAsync("/api/auth/magic-link/callback", new { t = token });
        Assert.That(callback.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var json = await JsonDocument.ParseAsync(await callback.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("mfa_required"));

        var handshakeToken = json.RootElement.GetProperty("handshakeToken").GetString();
        Assert.That(handshakeToken, Is.Not.Null.And.Not.Empty);

        var verify = await client.PostAsJsonAsync("/api/mfa/verify", new { handshakeToken, code = recoveryCode });
        Assert.That(verify.StatusCode, Is.EqualTo(HttpStatusCode.OK), await verify.Content.ReadAsStringAsync());
    }

    private static async Task AssertAuthenticatedPageAsync(HttpClient client, string path)
    {
        var response = await client.GetAsync(path);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private static async Task AssertAdminPageIncludesAccountSecurityPanelAsync(HttpClient client)
    {
        var response = await client.GetAsync("/admin");
        var html = await response.Content.ReadAsStringAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("Account Security"));
            Assert.That(html, Does.Contain("securityUserId"));
            Assert.That(html, Does.Contain("disableUserBtn"));
            Assert.That(html, Does.Contain("resetUserMfaBtn"));
        }
    }

    private static async Task AssertLastAdminCannotBeDisabledAsync(HttpClient client, Guid adminUserId)
    {
        var response = await client.PostAsJsonAsync($"/api/admin/users/{adminUserId}/disable", new { reason = "smoke-test" });
        var body = await response.Content.ReadAsStringAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound).Or.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(body, Does.Contain("last_admin_cannot_be_disabled"));
        }

        await AssertAuthenticatedPageAsync(client, "/admin");
    }

    private static async Task AssertForbiddenAsync(HttpClient client, string path)
    {
        var response = await client.GetAsync(path);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    private static async Task AssertStepUpForbiddenPostAsync(HttpClient client, string path, object? body)
    {
        var response = body == null
            ? await client.PostAsync(path, null)
            : await client.PostAsJsonAsync(path, body);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden), await response.Content.ReadAsStringAsync());
            Assert.That(response.Headers.TryGetValues("X-Ashlar-Step-Up", out var values), Is.True);
            Assert.That(values, Does.Contain("required"));
        }
    }

    private static async Task AssertGoogleUiHiddenWhenNotConfiguredAsync(HttpClient client)
    {
        var dashboard = await client.GetAsync("/");
        var invitation = await client.GetAsync("/invitations/accept?t=sample-token");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(await dashboard.Content.ReadAsStringAsync(), Does.Not.Contain("Sign in with Google"));
            Assert.That(await invitation.Content.ReadAsStringAsync(), Does.Not.Contain("Sign up with Google"));
        }
    }

    private static async Task<JsonDocument> GetJsonAsync(HttpClient client, string path)
    {
        var response = await client.GetAsync(path);
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), body);
        return JsonDocument.Parse(body);
    }

    private async Task<string> LatestOutboxBodyAsync(string toAddress, string subject)
    {
        await using var connection = new NpgsqlConnection(GetConnectionString());
        var body = await connection.QueryFirstOrDefaultAsync<string?>("""
            SELECT text_body
            FROM ashlar_email_outbox
            WHERE lower(to_address) = lower(@ToAddress)
              AND subject = @Subject
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """, new { ToAddress = toAddress, Subject = subject });

        var observed = await connection.QueryAsync<string>("""
            SELECT to_address || '|' || subject
            FROM ashlar_email_outbox
            ORDER BY created_at, id
            """);

        Assert.That(body, Is.Not.Null.And.Not.Empty, $"Expected email to {toAddress} with subject '{subject}'. Observed: {string.Join(", ", observed)}");
        return body!;
    }

    private static string ExtractQueryValue(string text, string name)
    {
        var match = Regex.Match(text, "[?&]" + Regex.Escape(name) + "=([^&\\s]+)", RegexOptions.CultureInvariant);
        Assert.That(match.Success, Is.True, $"Expected query parameter '{name}' in: {text}");
        return Uri.UnescapeDataString(match.Groups[1].Value);
    }

    private static string ExtractSharedSecret(string html)
    {
        var match = SharedSecretInputRegex().Match(html);
        Assert.That(match.Success, Is.True);
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    private static string GenerateTotpCode(string sharedSecret)
    {
        var key = DecodeBase32(sharedSecret);
        var counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        Span<byte> counterBytes = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);

#pragma warning disable CA5350 // HMAC-SHA1 is required by RFC 6238 TOTP.
        var hash = HMACSHA1.HashData(key, counterBytes);
#pragma warning restore CA5350
        var offset = hash[^1] & 0x0F;
        var binaryCode = ((hash[offset] & 0x7F) << 24)
            | ((hash[offset + 1] & 0xFF) << 16)
            | ((hash[offset + 2] & 0xFF) << 8)
            | (hash[offset + 3] & 0xFF);

        return (binaryCode % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    private static byte[] DecodeBase32(string value)
    {
        var output = new List<byte>();
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var character in value.Where(c => c != '='))
        {
            var index = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".IndexOf(char.ToUpperInvariant(character), StringComparison.Ordinal);
            Assert.That(index, Is.GreaterThanOrEqualTo(0));

            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                output.Add((byte)((buffer >> (bitsLeft - 8)) & 0xFF));
                bitsLeft -= 8;
            }
        }

        return [.. output];
    }

    [GeneratedRegex("""\b\d{6}\b""", RegexOptions.CultureInvariant)]
    private static partial Regex SixDigitCodeRegex();

    [GeneratedRegex("id=\"secret\" value=\"([^\"]+)\"", RegexOptions.CultureInvariant)]
    private static partial Regex SharedSecretInputRegex();

    private sealed class SampleApplicationFactory(
        string connectionString,
        IReadOnlyDictionary<string, string?>? additionalConfiguration = null,
        bool maskGoogleConfiguration = true) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration(configuration =>
            {
                var values = new Dictionary<string, string?>
                {
                    ["Ashlar:ConnectionString"] = connectionString,
                    ["Ashlar:PublicAppUrl"] = "http://localhost",
                    ["Ashlar:Cookie:Secure"] = "false",
                    ["Ashlar:Outbox:PollingInterval"] = "01:00:00",
                    ["Ashlar:Cleanup:CleanupInterval"] = "01:00:00"
                };

                if (maskGoogleConfiguration)
                {
                    values["Authentication:Google:ClientId"] = string.Empty;
                    values["Authentication:Google:ClientSecret"] = string.Empty;
                    values["Authentication:Google:HostedDomains:0"] = string.Empty;
                }

                if (additionalConfiguration != null)
                {
                    foreach (var (key, value) in additionalConfiguration)
                    {
                        values[key] = value;
                    }
                }

                configuration.AddInMemoryCollection(values);
            });

            builder.ConfigureServices(services =>
            {
                services.AddSingleton<IStartupFilter, TestServerRemoteIpStartupFilter>();

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
    }

    private sealed class TestServerRemoteIpStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                app.Use(async (context, nextMiddleware) =>
                {
                    context.Connection.RemoteIpAddress ??= IPAddress.Loopback;
                    await nextMiddleware();
                });

                next(app);
            };
        }
    }
}
