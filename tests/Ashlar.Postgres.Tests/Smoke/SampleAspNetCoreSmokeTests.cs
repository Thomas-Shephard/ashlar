using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Ashlar.Authorization.Models;
using Ashlar.AspNetCore.Authorization;
using Ashlar.Identity.Models.Totp;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Dapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;

namespace Ashlar.Postgres.Tests.Smoke;

internal sealed partial class SampleAspNetCoreSmokeTests : PostgresTestBase
{
    private const string TestRemoteIpHeader = "X-Ashlar-Test-Remote-Ip";
    private SampleApplicationFactory? _factory;
    private HttpClient? _adminClient;
    private int _nextRemoteIpOctet = 10;
    private readonly Dictionary<string, string?> _previousEnvironmentValues = new(StringComparer.Ordinal);

    private HttpClient AdminClient => _adminClient ?? throw new InvalidOperationException("The test client has not been initialized.");

    private string NextTestRemoteIpAddress()
    {
        return $"203.0.113.{Interlocked.Increment(ref _nextRemoteIpOctet)}";
    }

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        SetSampleEnvironment("Ashlar__ConnectionString", GetConnectionString());
        SetSampleEnvironment("Ashlar__PublicAppUrl", "http://localhost");
        SetSampleEnvironment("Ashlar__Bootstrap__SetupSecret", "sample-bootstrap-secret");
        SetSampleEnvironment("Ashlar__Cookie__Secure", "false");
        SetSampleEnvironment("Ashlar__Outbox__PollingInterval", "01:00:00");
        SetSampleEnvironment("Ashlar__Cleanup__CleanupInterval", "01:00:00");
        SetSampleEnvironment("Authentication__Google__ClientId", string.Empty);
        SetSampleEnvironment("Authentication__Google__ClientSecret", string.Empty);
        SetSampleEnvironment("Authentication__Google__HostedDomains__0", string.Empty);
        SetSampleEnvironment("Authentication__GitHub__ClientId", string.Empty);
        SetSampleEnvironment("Authentication__GitHub__ClientSecret", string.Empty);

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
        var adminUserId = await BootstrapFirstAdminAsync();
        await AssertGoogleUiHiddenWhenNotConfiguredAsync(AdminClient);
        await AssertGitHubUiHiddenWhenNotConfiguredAsync(AdminClient);
        await AssertAdminPageIncludesAccountSecurityPanelAsync(AdminClient);
        await AssertSampleAntiforgeryProtectionAsync(AdminClient);
        await AssertLogoutAntiforgeryProtectionAsync();
        var adminTotpSecret = await EnrollTotpAsync(AdminClient, adminUserId);
        await AssertLastAdminCannotBeDisabledAsync(AdminClient, adminUserId, adminTotpSecret);
        await AssertSampleAdminTenantScopeAsync(adminUserId);
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

        var sharedSecret = await EnrollTotpAsync(memberClient, invitedUserId);
        var recoveryCodes = await GenerateRecoveryCodesAsync(memberClient, sharedSecret);

        await ExpireCurrentStepUpAsync(invitedUserId);
        await AssertStepUpForbiddenPostAsync(memberClient, "/api/mfa/recovery-codes", null);
        await StepUpWithRecoveryCodeAsync(memberClient, recoveryCodes[0]);
        recoveryCodes = await GenerateRecoveryCodesAsync(memberClient, sharedSecret);

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

    private async Task AssertSampleAdminTenantScopeAsync(Guid adminUserId)
    {
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();

        var globalUserId = await CreateSampleUserAsync(_factory!.Services, $"global-{Guid.NewGuid():N}@example.com");
        var tenantAdminEmail = $"tenant-admin-{Guid.NewGuid():N}@example.com";
        var tenantAdminId = await CreateSampleUserAsync(_factory.Services, tenantAdminEmail, tenantId);
        var tenantMemberId = await CreateSampleUserAsync(_factory.Services, $"tenant-member-{Guid.NewGuid():N}@example.com", tenantId);
        await CreateSampleUserAsync(_factory.Services, $"other-tenant-{Guid.NewGuid():N}@example.com", otherTenantId);

        await GrantAdminRoleAsync(_factory.Services, tenantAdminId, tenantId);

        var globalUsers = await GetJsonAsync(AdminClient, "/api/admin/users");
        using var forbiddenTenantRequest = new HttpRequestMessage(HttpMethod.Get, "/api/admin/users");
        forbiddenTenantRequest.Headers.Add("X-Tenant-Id", tenantId.ToString("D"));
        var forbiddenTenantResponse = await AdminClient.SendAsync(forbiddenTenantRequest);
        using var forbiddenTenantSecurityRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/admin/users/{tenantMemberId}/security");
        forbiddenTenantSecurityRequest.Headers.Add("X-Tenant-Id", tenantId.ToString("D"));
        var forbiddenTenantSecurityResponse = await AdminClient.SendAsync(forbiddenTenantSecurityRequest);
        using var forbiddenProjectCatalogRequest = new HttpRequestMessage(HttpMethod.Get, "/api/admin/projects");
        forbiddenProjectCatalogRequest.Headers.Add("X-Tenant-Id", tenantId.ToString("D"));
        var forbiddenProjectCatalogResponse = await AdminClient.SendAsync(forbiddenProjectCatalogRequest);

        using var tenantAdminClient = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        AddTenantHeader(tenantAdminClient, tenantId);
        await SignInWithMagicLinkAsync(tenantAdminClient, tenantAdminEmail);
        var tenantAdminTotpSecret = await EnrollTotpAsync(tenantAdminClient, tenantAdminId);

        var tenantUsers = await GetJsonAsync(tenantAdminClient, "/api/admin/users");
        await ExpireCurrentStepUpAsync(tenantAdminId);
        await AssertStepUpForbiddenGetAsync(tenantAdminClient, $"/api/admin/users/{tenantMemberId}/security");
        await VerifyCurrentSessionWithTotpAsync(tenantAdminClient, tenantAdminTotpSecret);
        var tenantSecurity = await tenantAdminClient.GetAsync($"/api/admin/users/{tenantMemberId}/security");
        var tenantSecurityJson = await tenantSecurity.Content.ReadFromJsonAsync<JsonElement>();
        await using var auditConnection = new NpgsqlConnection(GetConnectionString());
        var tenantSecurityAuditCount = await auditConnection.ExecuteScalarAsync<int>("""
            SELECT count(*) FROM ashlar_security_events
            WHERE event_type = 'administration.read' AND actor_user_id = @ActorUserId
              AND tenant_id = @TenantId AND outcome = 'success' AND properties->>'operation' = 'ReadUser'
            """, new { ActorUserId = tenantAdminId, TenantId = tenantId });
        var tenantGrant = await PostAsJsonWithCsrfAsync(tenantAdminClient, "/api/projects/alpha/grants", new { userId = tenantMemberId });
        var projectGrantTenantId = await GetProjectGrantTenantIdAsync(tenantMemberId, "alpha");
        var disableTenantMember = await PostAsJsonWithCsrfAsync(tenantAdminClient, $"/api/admin/users/{tenantMemberId}/disable", new { reason = "tenant-scope-test" });
        var reactivateTenantMember = await PostAsJsonWithCsrfAsync(tenantAdminClient, $"/api/admin/users/{tenantMemberId}/account-state", new { accountState = UserAccountState.Active, reason = "tenant-scope-test" });
        var disableGlobalUser = await PostAsJsonWithCsrfAsync(tenantAdminClient, $"/api/admin/users/{globalUserId}/disable", new { reason = "tenant-scope-test" });
        var globalUserState = await GetAccountStateAsync(globalUserId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Ids(globalUsers), Does.Contain(adminUserId));
            Assert.That(Ids(globalUsers), Does.Contain(globalUserId));
            Assert.That(Ids(globalUsers), Does.Not.Contain(tenantAdminId));
            Assert.That(Ids(globalUsers), Does.Not.Contain(tenantMemberId));
            Assert.That(forbiddenTenantResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(forbiddenTenantSecurityResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(forbiddenProjectCatalogResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(Ids(tenantUsers), Does.Contain(tenantAdminId));
            Assert.That(Ids(tenantUsers), Does.Contain(tenantMemberId));
            Assert.That(Ids(tenantUsers), Does.Not.Contain(adminUserId));
            Assert.That(Ids(tenantUsers), Does.Not.Contain(globalUserId));
            Assert.That(tenantSecurity.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(tenantSecurityJson.TryGetProperty("user", out _), Is.False);
            Assert.That(tenantSecurityJson.GetProperty("userId").GetGuid(), Is.EqualTo(tenantMemberId));
            Assert.That(tenantSecurityAuditCount, Is.EqualTo(1));
            Assert.That(tenantGrant.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(projectGrantTenantId, Is.EqualTo(tenantId));
            Assert.That(disableTenantMember.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(reactivateTenantMember.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(disableGlobalUser.StatusCode, Is.Not.EqualTo(HttpStatusCode.OK));
            Assert.That(globalUserState, Is.EqualTo("active"));
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
            var invitationCallbackHtml = await invitationCallback.Content.ReadAsStringAsync();

            using (Assert.EnterMultipleScope())
            {
                Assert.That(signIn.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
                Assert.That(signIn.Headers.Location?.Host, Does.Contain("google"));
                Assert.That(await signInCallback.Content.ReadAsStringAsync(), Does.Contain("Google Sign-In Failed"));
                Assert.That(invitationHtml, Does.Contain("Sign up with Google"));
                Assert.That(invitationStart.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
                Assert.That(invitationStart.Headers.Location?.Host, Does.Contain("google"));
                Assert.That(invitationCallbackHtml, Does.Contain("Invitation Could Not Be Accepted"));
                Assert.That(invitationCallback.Headers.GetValues("Set-Cookie"), Has.Some.Contains("Ashlar.OAuth.External").And.Contains("expires="));
                Assert.That(invitationCallbackHtml, Does.Not.Contain("external-subject"));
                Assert.That(invitationCallbackHtml, Does.Not.Contain("external-token"));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("Authentication__Google__ClientId", string.Empty);
            Environment.SetEnvironmentVariable("Authentication__Google__ClientSecret", string.Empty);
            Environment.SetEnvironmentVariable("Authentication__Google__HostedDomains__0", string.Empty);
        }
    }

    [Test]
    public async Task SampleGitHubOAuthWiringIsConditionalAndFailsSafelyWithoutExternalTicket()
    {
        var missingGitHubSignIn = await AdminClient.GetAsync("/auth/github");
        Assert.That(missingGitHubSignIn.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));

        Environment.SetEnvironmentVariable("Authentication__GitHub__ClientId", "sample-client-id");
        Environment.SetEnvironmentVariable("Authentication__GitHub__ClientSecret", "sample-client-secret");
        try
        {
            await using var githubFactory = new SampleApplicationFactory(GetConnectionString(), maskGitHubConfiguration: false);
            using var client = githubFactory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

            var signIn = await client.GetAsync("/auth/github");
            var signInCallback = await client.GetAsync("/auth/github/callback");
            var invitationPage = await client.GetAsync("/invitations/accept?t=sample-token");
            var invitationHtml = await invitationPage.Content.ReadAsStringAsync();
            var invitationStart = await client.GetAsync("/invitations/accept/github?t=sample-token&userName=Member");
            var invitationCallback = await client.GetAsync("/invitations/accept/github/callback");

            using (Assert.EnterMultipleScope())
            {
                Assert.That(signIn.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
                Assert.That(signIn.Headers.Location?.Host, Does.Contain("github"));
                Assert.That(await signInCallback.Content.ReadAsStringAsync(), Does.Contain("GitHub Sign-In Failed"));
                Assert.That(invitationHtml, Does.Not.Contain("Sign up with GitHub"));
                Assert.That(invitationStart.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(invitationCallback.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("Authentication__GitHub__ClientId", string.Empty);
            Environment.SetEnvironmentVariable("Authentication__GitHub__ClientSecret", string.Empty);
        }

        await AssertGitHubCallbackUsesOrchestrationBeforeSessionAsync();
    }

    [Test]
    public async Task SampleMfaCompletedSignInUsesVerifiedSessionHelperWithCleanup()
    {
        await AssertSampleMfaCompletedSignInUsesVerifiedSessionHelperWithCleanupAsync();
    }

    [Test]
    public async Task SamplePasswordlessVerificationUsesSignInServices()
    {
        await AssertSamplePasswordlessVerificationUsesSignInServicesAsync();
    }

    [Test]
    public async Task SampleGoogleInvitationCallbackClearsMalformedExternalTicket()
    {
        Environment.SetEnvironmentVariable("Authentication__Google__ClientId", "sample-client-id");
        Environment.SetEnvironmentVariable("Authentication__Google__ClientSecret", "sample-client-secret");
        Environment.SetEnvironmentVariable("Authentication__Google__HostedDomains__0", "example.com");
        try
        {
            await using var googleFactory = new SampleApplicationFactory(GetConnectionString(), maskGoogleConfiguration: false);
            using var client = googleFactory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

            var seed = await client.GetAsync("/__test/external-google-ticket");
            var callback = await client.GetAsync("/invitations/accept/google/callback");
            var html = await callback.Content.ReadAsStringAsync();

            using (Assert.EnterMultipleScope())
            {
                Assert.That(seed.StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
                Assert.That(html, Does.Contain("Invitation Could Not Be Accepted"));
                Assert.That(callback.Headers.GetValues("Set-Cookie"), Has.Some.Contains("Ashlar.OAuth.External").And.Contains("expires="));
                Assert.That(html, Does.Not.Contain("external-subject"));
                Assert.That(html, Does.Not.Contain("external-token"));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("Authentication__Google__ClientId", string.Empty);
            Environment.SetEnvironmentVariable("Authentication__Google__ClientSecret", string.Empty);
            Environment.SetEnvironmentVariable("Authentication__Google__HostedDomains__0", string.Empty);
        }
    }

    [Test]
    public void SampleStartupFailsWhenBootstrapSetupSecretIsMissing()
    {
        var previousSecret = Environment.GetEnvironmentVariable("Ashlar__Bootstrap__SetupSecret");
        try
        {
            Environment.SetEnvironmentVariable("Ashlar__Bootstrap__SetupSecret", null);
            var exception = Assert.Throws<InvalidOperationException>(() =>
            {
                using var factory = new SampleApplicationFactory(GetConnectionString());
                using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            });

            Assert.That(exception?.Message, Does.Contain("Ashlar:Bootstrap:SetupSecret"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("Ashlar__Bootstrap__SetupSecret", previousSecret);
        }
    }

    [Test]
    public void SampleAdminCreationEndpointsRequireOnlyStrictFreshMfa()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(StepUpPoliciesFor("POST", "/api/admin/projects"), Is.EqualTo(new[] { AshlarStepUpPolicyNames.FreshMfa }));
            Assert.That(StepUpPoliciesFor("POST", "/api/projects/{projectId}/grants"), Is.EqualTo(new[] { AshlarStepUpPolicyNames.FreshMfa }));
            Assert.That(StepUpPoliciesFor("POST", "/api/invitations"), Is.EqualTo(new[] { AshlarStepUpPolicyNames.FreshMfa }));
            Assert.That(StepUpPoliciesFor("GET", "/api/admin/users"), Is.EqualTo(new[] { AshlarStepUpPolicyNames.FreshMfa }));
            Assert.That(StepUpPoliciesFor("GET", "/api/admin/users/{userId:guid}/security"), Is.EqualTo(new[] { AshlarStepUpPolicyNames.FreshMfa }));
            Assert.That(StepUpPoliciesFor("GET", "/api/admin/projects"), Is.Empty);
            Assert.That(StepUpPoliciesFor("POST", "/api/invitations/accept"), Is.Empty);
        }
    }

    [Test]
    public async Task SampleGitHubAccountSecurityRoutesRequireAuthorizationAndFreshMfaWhenAvailable()
    {
        Environment.SetEnvironmentVariable("Authentication__GitHub__ClientId", "sample-client-id");
        Environment.SetEnvironmentVariable("Authentication__GitHub__ClientSecret", "sample-client-secret");
        try
        {
            await using var githubFactory = new SampleApplicationFactory(GetConnectionString(), maskGitHubConfiguration: false);

            using var anonymousClient = githubFactory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            var anonymousLink = await anonymousClient.GetAsync("/account/external/github/link");
            var anonymousUnlink = await anonymousClient.PostAsync("/api/account/external/github/unlink", null);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(anonymousLink.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
                Assert.That(anonymousUnlink.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            }

            var email = $"github-{Guid.NewGuid():N}@example.com";
            var userId = await CreateSampleUserAsync(githubFactory.Services, email);
            using var client = githubFactory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            await SignInWithMagicLinkAsync(client, email);

            var unlinkedAccountPage = await client.GetAsync("/account");
            var unlinkedHtml = await unlinkedAccountPage.Content.ReadAsStringAsync();
            using (Assert.EnterMultipleScope())
            {
                Assert.That(unlinkedAccountPage.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                Assert.That(unlinkedHtml, Does.Contain("GitHub Account"));
                Assert.That(unlinkedHtml, Does.Contain("GitHub sign-in"));
                Assert.That(unlinkedHtml, Does.Contain("Not linked"));
                Assert.That(unlinkedHtml, Does.Not.Contain("sample-client-secret"));
            }

            await LinkGitHubCredentialAsync(githubFactory.Services, userId);
            var linkedAccountPage = await client.GetAsync("/account");
            var linkedHtml = await linkedAccountPage.Content.ReadAsStringAsync();
            using (Assert.EnterMultipleScope())
            {
                Assert.That(linkedAccountPage.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                Assert.That(linkedHtml, Does.Contain("GitHub Account"));
                Assert.That(linkedHtml, Does.Contain("Linked"));
                Assert.That(linkedHtml, Does.Not.Contain($"github-{userId:N}"));
            }

            await EnrollTotpAsync(client, userId);
            await ExpireCurrentStepUpAsync(userId);
            await AssertStepUpForbiddenGetAsync(client, "/account/external/github/link");
            await AssertStepUpForbiddenPostAsync(client, "/api/account/external/github/unlink", null);
        }
        finally
        {
            Environment.SetEnvironmentVariable("Authentication__GitHub__ClientId", string.Empty);
            Environment.SetEnvironmentVariable("Authentication__GitHub__ClientSecret", string.Empty);
        }
    }

    private async Task<Guid> BootstrapFirstAdminAsync()
    {
        var publicResponse = await AdminClient.PostAsJsonAsync("/api/bootstrap/first-admin", new { email = "public@example.com", userName = "Public" });
        Assert.That(publicResponse.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        using (var publicJson = await JsonDocument.ParseAsync(await publicResponse.Content.ReadAsStreamAsync()))
        {
            Assert.That(publicJson.RootElement.GetProperty("error").GetString(), Is.EqualTo("bootstrap_request_failed"));
        }

        using var malformedContent = new StringContent("{", System.Text.Encoding.UTF8, "application/json");
        var malformedResponse = await AdminClient.PostAsync("/api/bootstrap/first-admin", malformedContent);
        Assert.That(malformedResponse.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        using (var malformedJson = await JsonDocument.ParseAsync(await malformedResponse.Content.ReadAsStreamAsync()))
        {
            Assert.That(malformedJson.RootElement.GetProperty("error").GetString(), Is.EqualTo("bootstrap_request_failed"));
        }

        var response = await AdminClient.PostAsJsonAsync("/api/bootstrap/first-admin", new { email = "admin@example.com", userName = "Admin", setupSecret = "sample-bootstrap-secret" });
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

        var revokeOthers = await DeleteWithCsrfAsync(client, "/api/sessions/others");
        Assert.That(revokeOthers.StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
    }

    private static async Task AssertSampleAntiforgeryProtectionAsync(HttpClient client)
    {
        var token = await GetCsrfTokenAsync(client);
        Assert.That(token, Is.Not.Empty);

        var missingToken = await client.PostAsJsonAsync("/api/account/profile", new { name = "Missing CSRF" });
        var missingBody = await missingToken.Content.ReadAsStringAsync();

        using var invalidRequest = new HttpRequestMessage(HttpMethod.Post, "/api/account/profile")
        {
            Content = JsonContent.Create(new { name = "Invalid CSRF" })
        };
        invalidRequest.Headers.Add("X-CSRF-TOKEN", "invalid-token");
        var invalidToken = await client.SendAsync(invalidRequest);
        var invalidBody = await invalidToken.Content.ReadAsStringAsync();

        var validToken = await PostAsJsonWithCsrfAsync(client, "/api/account/security/verify", new { code = "000000" });
        var validBody = await validToken.Content.ReadAsStringAsync();

        var missingAdminToken = await client.PostAsJsonAsync("/api/invitations", new { email = "csrf-admin@example.com" });
        var missingAdminBody = await missingAdminToken.Content.ReadAsStringAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingToken.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(missingBody, Does.Contain("invalid_csrf_token"));
            Assert.That(invalidToken.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(invalidBody, Does.Contain("invalid_csrf_token"));
            Assert.That(validToken.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(validBody, Does.Contain("invalid_totp"));
            Assert.That(missingAdminToken.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(missingAdminBody, Is.Empty);
        }
    }

    private async Task AssertLogoutAntiforgeryProtectionAsync()
    {
        using var client = _factory!.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await SignInWithMagicLinkAsync(client, "admin@example.com");

        var missingToken = await client.PostAsync("/api/auth/logout", null);
        var missingBody = await missingToken.Content.ReadAsStringAsync();

        var logout = await PostWithCsrfAsync(client, "/api/auth/logout");
        var accountAfterLogout = await client.GetAsync("/account");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingToken.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(missingBody, Does.Contain("invalid_csrf_token"));
            Assert.That(logout.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(logout.Headers.Location?.OriginalString, Is.EqualTo("/"));
            Assert.That(accountAfterLogout.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }
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
        var response = await PostAsJsonWithCsrfAsync(AdminClient, "/api/invitations", new { email });
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
        var response = await PostAsJsonWithCsrfAsync(AdminClient, $"/api/projects/{projectId}/grants", new { userId });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private async Task SignInWithMagicLinkAsync(HttpClient client, string email)
    {
        client.DefaultRequestHeaders.Remove(TestRemoteIpHeader);
        client.DefaultRequestHeaders.Add(TestRemoteIpHeader, NextTestRemoteIpAddress());
        var requested = await client.PostAsJsonAsync("/api/auth/magic-link/request", new { email });
        Assert.That(requested.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

        var token = ExtractQueryValue(await LatestOutboxBodyAsync(email, "Sign in to our application"), "t");
        var callback = await client.PostAsJsonAsync("/api/auth/magic-link/callback", new { t = token });
        Assert.That(callback.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private async Task VerifyEmailAsync(HttpClient client, string email)
    {
        var request = await PostWithCsrfAsync(client, "/api/account/verify-email/request");
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
            WHERE normalized_email = upper(@Email)
            """, new { Email = email });

        Assert.That(rows, Is.EqualTo(1));
    }

    private async Task ChangeEmailAsync(HttpClient client, string oldEmail, string newEmail)
    {
        var request = await PostAsJsonWithCsrfAsync(client, "/api/account/change-email/request", new { newEmail });
        Assert.That(request.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

        var body = await LatestOutboxBodyAsync(newEmail, "Confirm your new email address");
        var token = ExtractQueryValue(body, "t");
        var userId = ExtractQueryValue(body, "u");

        var confirm = await client.PostAsJsonAsync($"/api/account/change-email/confirm?u={Uri.EscapeDataString(userId)}", new { token });
        Assert.That(confirm.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var oldAddressCodeRequest = await client.PostAsJsonAsync("/api/auth/email-code/request", new { email = oldEmail });
        Assert.That(oldAddressCodeRequest.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));
    }

    private async Task<string> EnrollTotpAsync(HttpClient client, Guid userId)
    {
        await MarkActiveSessionsFreshAsync(userId);
        var page = await client.GetAsync("/account/mfa/enroll");
        var pageBody = await page.Content.ReadAsStringAsync();
        if (page.StatusCode == HttpStatusCode.Forbidden)
        {
            return await EnrollTotpForAccountRecoverySmokeAsync(userId);
        }

        Assert.That(page.StatusCode, Is.EqualTo(HttpStatusCode.OK), pageBody);

        var html = pageBody;
        var sharedSecret = ExtractSharedSecret(html);
        var code = GenerateTotpCode(sharedSecret);

        var verify = await PostAsJsonWithCsrfAsync(client, "/api/mfa/totp/verify", new { sharedSecret, code });
        Assert.That(verify.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        return sharedSecret;
    }

    private async Task<string> EnrollTotpForAccountRecoverySmokeAsync(Guid userId)
    {
        await using var scope = _factory!.Services.CreateAsyncScope();
        const string secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        await scope.ServiceProvider.GetRequiredService<ICredentialRepository>().CreateCredentialAsync(new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = TotpOptions.DefaultProviderKey.Type,
            ProviderName = TotpOptions.DefaultProviderKey.Name,
            ProviderKey = userId.ToString("D"),
            Version = Guid.NewGuid().ToString("N"),
            CredentialValue = secret,
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        });
        await MarkActiveSessionsFreshAsync(userId);
        return secret;
    }

    private async Task MarkActiveSessionsFreshAsync(Guid userId)
    {
        await using var connection = new NpgsqlConnection(GetConnectionString());
        var rows = await connection.ExecuteAsync("""
            UPDATE ashlar_sessions
            SET additional_verification_at = now(),
                additional_verification_provider_type = @ProviderType,
                additional_verification_provider_name = @ProviderName,
                additional_verification_factor = @Factor
            WHERE revoked_at IS NULL
              AND expires_at > now()
              AND user_id = @UserId
            """, new
        {
            UserId = userId,
            ProviderType = ProviderType.Mfa.StorageValue,
            ProviderName = "totp",
            Factor = "totp"
        });

        Assert.That(rows, Is.GreaterThanOrEqualTo(1));
    }

    private static async Task<IReadOnlyList<string>> GenerateRecoveryCodesAsync(HttpClient client, string? totpSecret = null)
    {
        var response = await PostWithCsrfAsync(client, "/api/mfa/recovery-codes");
        if (response.StatusCode == HttpStatusCode.Forbidden && totpSecret != null)
        {
            await VerifyCurrentSessionWithTotpAsync(client, totpSecret);
            response = await PostWithCsrfAsync(client, "/api/mfa/recovery-codes");
        }

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
        var response = await PostAsJsonWithCsrfAsync(client, "/api/account/security/verify", new { code = recoveryCode });
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

    private async Task AssertLastAdminCannotBeDisabledAsync(HttpClient client, Guid adminUserId, string totpSecret)
    {
        await MarkActiveSessionsFreshAsync(adminUserId);
        var response = await PostAsJsonWithCsrfAsync(client, $"/api/admin/users/{adminUserId}/disable", new { reason = "smoke-test" });
        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            await VerifyCurrentSessionWithTotpAsync(client, totpSecret);
            response = await PostAsJsonWithCsrfAsync(client, $"/api/admin/users/{adminUserId}/disable", new { reason = "smoke-test" });
        }

        var body = await response.Content.ReadAsStringAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound).Or.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(body, Does.Contain("last_admin_cannot_be_changed_to_non_sign_in_state"));
        }

        await AssertAuthenticatedPageAsync(client, "/admin");
    }

    private static async Task VerifyCurrentSessionWithTotpAsync(HttpClient client, string sharedSecret)
    {
        var response = await PostAsJsonWithCsrfAsync(client, "/api/account/security/verify", new { code = GenerateTotpCode(sharedSecret, stepOffset: 1) });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), await response.Content.ReadAsStringAsync());
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

    private static async Task AssertStepUpForbiddenGetAsync(HttpClient client, string path)
    {
        var response = await client.GetAsync(path);
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

    private static async Task AssertGitHubUiHiddenWhenNotConfiguredAsync(HttpClient client)
    {
        var dashboard = await client.GetAsync("/");
        var invitation = await client.GetAsync("/invitations/accept?t=sample-token");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(await dashboard.Content.ReadAsStringAsync(), Does.Not.Contain("Sign in with GitHub"));
            Assert.That(await invitation.Content.ReadAsStringAsync(), Does.Not.Contain("Sign up with GitHub"));
        }
    }

    private static async Task<Guid> CreateSampleUserAsync(IServiceProvider services, string email, Guid? tenantId = null)
    {
        await using var scope = services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<IUserRepository>();
        var user = new AshlarUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            Name = "GitHub Smoke",
            AccountState = UserAccountState.Active,
            TenantId = tenantId,
            EmailVerifiedAt = DateTimeOffset.UtcNow
        };

        await users.CreateUserAsync(user);
        return user.Id;
    }

    private static async Task GrantAdminRoleAsync(IServiceProvider services, Guid userId, Guid? tenantId)
    {
        await using var scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IAuthorizationGrantRepository>().CreateGrantAsync(new AuthorizationGrant
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TenantId = tenantId,
            Role = "admin",
            CreatedAt = DateTimeOffset.UtcNow
        });
    }

    private async Task<string> GetAccountStateAsync(Guid userId)
    {
        await using var connection = new NpgsqlConnection(GetConnectionString());
        return await connection.QuerySingleAsync<string>(
            "SELECT account_state FROM ashlar_users WHERE id = @UserId",
            new { UserId = userId });
    }

    private async Task<Guid?> GetProjectGrantTenantIdAsync(Guid userId, string projectId)
    {
        await using var connection = new NpgsqlConnection(GetConnectionString());
        return await connection.QuerySingleAsync<Guid?>("""
            SELECT tenant_id
            FROM ashlar_authorization_grants
            WHERE user_id = @UserId
              AND scope_type = 'project'
              AND scope_id = @ProjectId
              AND permission = 'project.manage'
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """, new { UserId = userId, ProjectId = projectId });
    }

    private static void AddTenantHeader(HttpClient client, Guid tenantId)
    {
        client.DefaultRequestHeaders.Remove("X-Tenant-Id");
        client.DefaultRequestHeaders.Add("X-Tenant-Id", tenantId.ToString("D"));
    }

    private static Guid[] Ids(JsonDocument document)
    {
        return document.RootElement.EnumerateArray().Select(user => user.GetProperty("id").GetGuid()).ToArray();
    }

    private static async Task LinkGitHubCredentialAsync(IServiceProvider services, Guid userId)
    {
        await using var scope = services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ICredentialRepository>().CreateCredentialAsync(new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.OAuth,
            ProviderName = "GitHub",
            ProviderKey = $"github-{userId:N}",
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        });
    }

    private static async Task AssertGitHubCallbackUsesOrchestrationBeforeSessionAsync()
    {
        var source = await File.ReadAllTextAsync(Path.Combine(
            LocateRepositoryRoot(),
            "samples",
            "Ashlar.Sample.AspNetCore",
            "Endpoints",
            "GitHubOAuthEndpoints.cs"));

        var assertionIndex = source.IndexOf("CompleteExternalAssertionAsync", StringComparison.Ordinal);
        var orchestratorIndex = source.IndexOf("orchestrator.AuthenticateAsync", StringComparison.Ordinal);
        var signInIndex = source.IndexOf("signInManager.SignInAsync", StringComparison.Ordinal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertionIndex, Is.GreaterThanOrEqualTo(0));
            Assert.That(orchestratorIndex, Is.GreaterThan(assertionIndex));
            Assert.That(signInIndex, Is.GreaterThan(orchestratorIndex));
            Assert.That(source, Does.Contain("new AuthenticationProviderKey(ProviderType.OAuth, SampleGitHubOAuth.ProviderName)"));
            Assert.That(source, Does.Not.Contain("CompleteExternalCredentialAuthenticationAsync"));
        }
    }

    private static async Task AssertSamplePasswordlessVerificationUsesSignInServicesAsync()
    {
        var source = await File.ReadAllTextAsync(Path.Combine(
            LocateRepositoryRoot(),
            "samples",
            "Ashlar.Sample.AspNetCore",
            "Endpoints",
            "AuthEndpoints.cs"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(source, Does.Contain("magicLinks.VerifyLinkAsync"));
            Assert.That(source, Does.Contain("emailCodes.VerifyCodeAsync"));
            Assert.That(source, Does.Not.Contain("new MagicLinkAssertion"));
            Assert.That(source, Does.Not.Contain("new EmailCodeAssertion"));
            Assert.That(source, Does.Not.Contain("orchestrator.AuthenticateAsync"));
        }
    }

    private static async Task AssertSampleMfaCompletedSignInUsesVerifiedSessionHelperWithCleanupAsync()
    {
        var root = LocateRepositoryRoot();
        var authExtensions = await File.ReadAllTextAsync(Path.Combine(
            root,
            "samples",
            "Ashlar.Sample.AspNetCore",
            "Extensions",
            "AuthExtensions.cs"));
        var mfaEndpoints = await File.ReadAllTextAsync(Path.Combine(
            root,
            "samples",
            "Ashlar.Sample.AspNetCore",
            "Endpoints",
            "MfaEndpoints.cs"));
        var passkeyEndpoints = await File.ReadAllTextAsync(Path.Combine(
            root,
            "samples",
            "Ashlar.Sample.AspNetCore",
            "Endpoints",
            "PasskeyEndpoints.cs"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(authExtensions, Does.Contain("SignInAndMarkStepUpVerifiedAsync"));
            Assert.That(authExtensions, Does.Contain("signInManager.SignInAsync"));
            Assert.That(authExtensions, Does.Contain("sessionService.MarkStepUpVerifiedAsync"));
            Assert.That(authExtensions, Does.Contain("if (!result.Succeeded)"));
            Assert.That(authExtensions, Does.Contain("catch"));
            Assert.That(authExtensions, Does.Contain("CleanupUnverifiedSessionAsync"));
            Assert.That(authExtensions, Does.Contain("sessionService.RevokeIssuedSessionAsync"));
            Assert.That(authExtensions, Does.Contain("signInManager.SignOutAsync"));
            Assert.That(authExtensions, Does.Contain("TenantContext.Global"));
            Assert.That(mfaEndpoints, Does.Contain("httpContext.SignInAndMarkStepUpVerifiedAsync"));
            Assert.That(mfaEndpoints, Does.Not.Contain("additionalVerificationProvider"));
            Assert.That(mfaEndpoints, Does.Not.Contain("AdditionalVerificationAt"));
            Assert.That(passkeyEndpoints, Does.Contain("httpContext.SignInAndMarkStepUpVerifiedAsync"));
            Assert.That(passkeyEndpoints, Does.Contain("AuthenticationFactorTypes.Passkey"));
            Assert.That(passkeyEndpoints, Does.Not.Contain("additionalVerificationProvider"));
            Assert.That(passkeyEndpoints, Does.Not.Contain("AdditionalVerificationAt"));
        }
    }

    private static string LocateRepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Ashlar.slnx")))
        {
            directory = directory.Parent;
        }

        Assert.That(directory, Is.Not.Null);
        return directory!.FullName;
    }

    private static async Task<JsonDocument> GetJsonAsync(HttpClient client, string path)
    {
        var response = await client.GetAsync(path);
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), body);
        return JsonDocument.Parse(body);
    }

    private static async Task<string> GetCsrfTokenAsync(HttpClient client)
    {
        var response = await client.GetAsync("/api/antiforgery/token");
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), body);
        using var json = JsonDocument.Parse(body);
        return json.RootElement.GetProperty("token").GetString() ?? string.Empty;
    }

    private static async Task<HttpResponseMessage> PostWithCsrfAsync(HttpClient client, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Headers.Add("X-CSRF-TOKEN", await GetCsrfTokenAsync(client));
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> PostAsJsonWithCsrfAsync<T>(HttpClient client, string path, T body)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Add("X-CSRF-TOKEN", await GetCsrfTokenAsync(client));
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> DeleteWithCsrfAsync(HttpClient client, string path)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, path);
        request.Headers.Add("X-CSRF-TOKEN", await GetCsrfTokenAsync(client));
        return await client.SendAsync(request);
    }

    private async Task<string> LatestOutboxBodyAsync(string toAddress, string subject)
    {
        await using var connection = new NpgsqlConnection(GetConnectionString());
        var row = await connection.QueryFirstOrDefaultAsync<OutboxBodyRow>("""
            SELECT text_body AS TextBody, body_protection AS BodyProtection
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

        Assert.That(row?.TextBody, Is.Not.Null.And.Not.Empty, $"Expected email to {toAddress} with subject '{subject}'. Observed: {string.Join(", ", observed)}");
        return row!.BodyProtection switch
        {
            nameof(EmailOutboxBodyProtection.None) => row.TextBody!,
            nameof(EmailOutboxBodyProtection.SecretProtector) => UnprotectOutboxBody(row.TextBody!),
            _ => throw new InvalidOperationException("Unexpected email outbox body protection value.")
        };
    }

    private string UnprotectOutboxBody(string textBody)
    {
        using var scope = _factory!.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<ISecretProtector>().Unprotect(textBody);
    }

    private string[] StepUpPoliciesFor(string method, string routePattern)
    {
        var endpoint = _factory!.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().Single(endpoint =>
            endpoint.RoutePattern.RawText == routePattern &&
            endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(method, StringComparer.OrdinalIgnoreCase) == true);

        return [.. endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
            .Select(metadata => metadata.Policy)
            .Where(policy => policy is AshlarStepUpPolicyNames.FreshMfa or AshlarStepUpPolicyNames.FreshMfaIfAvailable)!];
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

    private static string GenerateTotpCode(string sharedSecret, long stepOffset = 0)
    {
        var key = DecodeBase32(sharedSecret);
        var counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30 + stepOffset;
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
        bool maskGoogleConfiguration = true,
        bool maskGitHubConfiguration = true) : WebApplicationFactory<Program>
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

                if (maskGitHubConfiguration)
                {
                    values["Authentication:GitHub:ClientId"] = string.Empty;
                    values["Authentication:GitHub:ClientSecret"] = string.Empty;
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
                services.AddPostgresProviderContractTestServices();
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
                    if (context.Request.Headers.TryGetValue(TestRemoteIpHeader, out var remoteIp)
                        && IPAddress.TryParse(remoteIp.FirstOrDefault(), out var parsedRemoteIp))
                    {
                        context.Connection.RemoteIpAddress = parsedRemoteIp;
                    }

                    context.Connection.RemoteIpAddress ??= IPAddress.Loopback;
                    if (context.Request.Path == "/__test/external-google-ticket")
                    {
                        var identity = new ClaimsIdentity(
                            [
                                new Claim("sub", "external-subject"),
                                new Claim("email", "invitee@example.com"),
                                new Claim("email_verified", "true"),
                                new Claim("access_token", "external-token")
                            ],
                            "oidc");
                        var properties = new AuthenticationProperties();
                        properties.Items[".ashlar.oauth.providerName"] = "Google";
                        properties.Items[".ashlar.oauth.schemeName"] = "Google";
                        properties.Items[".ashlar.oauth.providerType"] = ProviderType.Oidc;

                        await context.SignInAsync(
                            "Ashlar.OAuth.External",
                            new ClaimsPrincipal(identity),
                            properties);
                        context.Response.StatusCode = StatusCodes.Status204NoContent;
                        return;
                    }

                    await nextMiddleware();
                });

                next(app);
            };
        }
    }

    private sealed class OutboxBodyRow
    {
        public string? TextBody { get; init; }
        public string? BodyProtection { get; init; }
    }
}
