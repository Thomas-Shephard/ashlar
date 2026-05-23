using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Ashlar.OAuth.Providers.Google;
using Ashlar.OAuth.Providers.Microsoft;

namespace Ashlar.OAuth.Tests;

internal sealed class AshlarOAuthServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarOAuthShouldRegisterGenericOidcProviderAndAshlarProvider()
    {
        var services = new ServiceCollection();

        services.AddAshlarOAuth(options =>
            options.AddOidcProvider(" Google ", oidc =>
            {
                oidc.Authority = "https://accounts.example.com";
                oidc.ClientId = "client";
                oidc.ClientSecret = "secret";
            }));

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var oauthOptions = provider.GetRequiredService<IOptionsMonitor<AshlarOAuthOptions>>().CurrentValue;
        var directOptions = provider.GetRequiredService<IOptions<AshlarOAuthOptions>>().Value;
        var snapshotOptions = scope.ServiceProvider.GetRequiredService<IOptionsSnapshot<AshlarOAuthOptions>>().Value;
        var authProviders = scope.ServiceProvider.GetServices<IAuthenticationProvider>().ToList();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(oauthOptions.OidcProviders, Does.ContainKey("Google"));
            Assert.That(directOptions.OidcProviders, Does.ContainKey("Google"));
            Assert.That(snapshotOptions.OidcProviders, Does.ContainKey("Google"));
            Assert.That(authProviders.Select(p => p.Key), Does.Contain(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(services.Any(d => d.ServiceType == typeof(AshlarExternalSignInService)), Is.True);
            Assert.That(services.Any(d => d.ServiceType == typeof(AshlarExternalAccountLinkService)), Is.True);
            Assert.That(services.Any(d => d.ServiceType == typeof(AshlarOidcInvitationRegistrationService)), Is.True);
            Assert.That(scope.ServiceProvider.GetRequiredService<IOidcInvitationEmailMatchPolicy>(), Is.TypeOf<StandardOidcVerifiedEmailMatchPolicy>());
        }
    }

    [Test]
    public void AddGoogleShouldRegisterExpectedProviderAndDefaults()
    {
        var options = new AshlarOAuthOptions();

        options.AddGoogle();

        var provider = options.OidcProviders["Google"];
        var oidc = new OpenIdConnectOptions();
        provider.Configure(oidc);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.ProviderName, Is.EqualTo("Google"));
            Assert.That(oidc.Authority, Is.EqualTo(GoogleOidcDefaults.Authority));
            Assert.That(oidc.ResponseType, Is.EqualTo("code"));
            Assert.That(oidc.Scope, Does.Contain("openid"));
            Assert.That(oidc.Scope, Does.Contain("profile"));
            Assert.That(oidc.Scope, Does.Contain("email"));
        }
    }

    [Test]
    public void AddGoogleShouldSupportCustomProviderName()
    {
        var options = new AshlarOAuthOptions();

        options.AddGoogle(providerName: "Google-Workspace");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.OidcProviders, Does.ContainKey("Google-Workspace"));
            Assert.That(options.OidcProviders["Google-Workspace"].ProviderName, Is.EqualTo("Google-Workspace"));
        }
    }

    [Test]
    public void AddOidcProviderShouldSupportCustomProviderKeyMode()
    {
        var options = new AshlarOAuthOptions();

        options.AddOidcProvider("SharedIssuer", AshlarOidcProviderKeyMode.IssuerAndSubject, _ => { });

        Assert.That(options.OidcProviders["SharedIssuer"].ProviderKeyMode, Is.EqualTo(AshlarOidcProviderKeyMode.IssuerAndSubject));
    }

    [Test]
    public void AddOidcProviderShouldRejectUnsupportedProviderKeyMode()
    {
        var options = new AshlarOAuthOptions();

        Assert.Throws<ArgumentOutOfRangeException>(() => options.AddOidcProvider("SharedIssuer", (AshlarOidcProviderKeyMode)42, _ => { }));
    }

    [Test]
    public async Task AddGoogleWithSingleHostedDomainShouldSetHostedDomainRedirectHint()
    {
        var oidc = ConfigureGoogleOptions(["yourcompany.com"]);
        var context = CreateRedirectContext(oidc);

        await oidc.Events.OnRedirectToIdentityProvider(context);

        Assert.That(context.ProtocolMessage.GetParameter("hd"), Is.EqualTo("yourcompany.com"));
    }

    [Test]
    public async Task AddGoogleWithMultipleHostedDomainsShouldSetWorkspaceRedirectHint()
    {
        var oidc = ConfigureGoogleOptions(["yourcompany.com", "example.com"]);
        var context = CreateRedirectContext(oidc);

        await oidc.Events.OnRedirectToIdentityProvider(context);

        Assert.That(context.ProtocolMessage.GetParameter("hd"), Is.EqualTo("*"));
    }

    [Test]
    public async Task AddGoogleHostedDomainsShouldAcceptMatchingHostedDomainClaim()
    {
        var oidc = ConfigureGoogleOptions(["yourcompany.com"]);
        var context = CreateTokenValidatedContext(oidc, "YOURCOMPANY.COM");

        await oidc.Events.OnTokenValidated(context);

        Assert.That(context.Result, Is.Null);
    }

    [Test]
    public async Task AddGoogleHostedDomainsShouldRejectMissingHostedDomainClaim()
    {
        var oidc = ConfigureGoogleOptions(["yourcompany.com"]);
        var context = CreateTokenValidatedContext(oidc, hostedDomain: null);

        await oidc.Events.OnTokenValidated(context);

        Assert.That(context.Result?.Failure, Is.Not.Null);
    }

    [Test]
    public async Task AddGoogleHostedDomainsShouldRejectInvalidHostedDomainClaim()
    {
        var oidc = ConfigureGoogleOptions(["yourcompany.com"]);
        var context = CreateTokenValidatedContext(oidc, "other.com");

        await oidc.Events.OnTokenValidated(context);

        Assert.That(context.Result?.Failure, Is.Not.Null);
    }

    [Test]
    public void AddAshlarOAuthShouldConfigureRemoteHandlerForExternalCookieAndProviderCallback()
    {
        var services = new ServiceCollection();

        services.AddAshlarOAuth(options => options.AddGoogle(oidc =>
        {
            oidc.ClientId = "client";
            oidc.ClientSecret = "secret";
        }));

        using var provider = services.BuildServiceProvider();
        var oidcOptions = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(oidcOptions.SignInScheme, Is.EqualTo("Ashlar.OAuth.External"));
            Assert.That(oidcOptions.CallbackPath.Value, Is.EqualTo("/signin-oidc/Google"));
            Assert.That(oidcOptions.SaveTokens, Is.False);
            Assert.That(oidcOptions.GetClaimsFromUserInfoEndpoint, Is.True);
            Assert.That(oidcOptions.MapInboundClaims, Is.False);
        }
    }

    [Test]
    public void AddAshlarOAuthShouldConfigureExternalCookieOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarOAuth(options => options.AddGoogle(oidc =>
        {
            oidc.ClientId = "client";
            oidc.ClientSecret = "secret";
        }));

        using var provider = services.BuildServiceProvider();
        var cookieOptions = provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Ashlar.OAuth.External");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(cookieOptions.Cookie.HttpOnly, Is.True);
            Assert.That(cookieOptions.Cookie.SameSite, Is.EqualTo(SameSiteMode.Lax));
            Assert.That(cookieOptions.ExpireTimeSpan, Is.EqualTo(TimeSpan.FromMinutes(5)));
            Assert.That(cookieOptions.SlidingExpiration, Is.False);
        }
    }

    [Test]
    public async Task AddAshlarOAuthShouldChainTicketReceivedEvent()
    {
        var called = false;
        var services = new ServiceCollection();
        services.AddAshlarOAuth(options => options.AddGoogle(oidc =>
        {
            oidc.ClientId = "client";
            oidc.ClientSecret = "secret";
            oidc.Events.OnTicketReceived = _ =>
            {
                called = true;
                return Task.CompletedTask;
            };
        }));
        using var provider = services.BuildServiceProvider();
        var oidcOptions = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Google");
        var context = new TicketReceivedContext(
            new DefaultHttpContext(),
            new AuthenticationScheme("Google", "Google", typeof(OpenIdConnectHandler)),
            oidcOptions,
            new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity("oidc")), new AuthenticationProperties(), "Google"));

        await oidcOptions.Events.OnTicketReceived(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(called, Is.True);
            Assert.That(context.Properties?.Items[AshlarOAuthAuthenticationProperties.ProviderName], Is.EqualTo("Google"));
            Assert.That(context.Properties?.Items[AshlarOAuthAuthenticationProperties.SchemeName], Is.EqualTo("Google"));
        }
    }

    [Test]
    public void AddAshlarOAuthShouldRejectMissingProviders()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddAshlarOAuth(_ => { }));
    }

    [Test]
    public void AddAshlarOAuthShouldRejectBlankExternalSignInScheme()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddAshlarOAuth(options =>
        {
            options.ExternalSignInScheme = " ";
            options.AddGoogle();
        }));
    }

    [Test]
    public void AddAshlarOAuthShouldRejectNullArguments()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarOAuthServiceCollectionExtensions.AddAshlarOAuth(null!, _ => { }));
            Assert.Throws<ArgumentNullException>(() => new ServiceCollection().AddAshlarOAuth(null!));
        }
    }

    [Test]
    public void AddAshlarOAuthShouldUseDecodedSchemeNameForCallbackPath()
    {
        var services = new ServiceCollection();

        services.AddAshlarOAuth(options => options.AddOidcProvider("Example Provider", oidc =>
        {
            oidc.Authority = "https://login.example.com";
            oidc.ClientId = "client";
            oidc.ClientSecret = "secret";
        }));

        using var provider = services.BuildServiceProvider();
        var oidcOptions = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Example Provider");

        Assert.That(oidcOptions.CallbackPath.Value, Is.EqualTo("/signin-oidc/Example Provider"));
    }

    [Test]
    public void AddAshlarOAuthShouldPreserveCustomCallbackPath()
    {
        var services = new ServiceCollection();

        services.AddAshlarOAuth(options => options.AddGoogle(oidc =>
        {
            oidc.ClientId = "client";
            oidc.ClientSecret = "secret";
            oidc.CallbackPath = "/custom-google-callback";
        }));

        using var provider = services.BuildServiceProvider();
        var oidcOptions = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Google");

        Assert.That(oidcOptions.CallbackPath.Value, Is.EqualTo("/custom-google-callback"));
    }

    [Test]
    public void AddAshlarOAuthShouldSetProviderCallbackPathWhenCallbackPathIsEmpty()
    {
        var services = new ServiceCollection();

        services.AddAshlarOAuth(options => options.AddGoogle(oidc =>
        {
            oidc.ClientId = "client";
            oidc.ClientSecret = "secret";
            oidc.CallbackPath = PathString.Empty;
        }));

        using var provider = services.BuildServiceProvider();
        var oidcOptions = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Google");

        Assert.That(oidcOptions.CallbackPath.Value, Is.EqualTo("/signin-oidc/Google"));
    }

    [Test]
    public void AddMicrosoftShouldRequireExplicitTenantAndRegisterExpectedAuthority()
    {
        var options = new AshlarOAuthOptions();

        options.AddMicrosoft("contoso.onmicrosoft.com");

        var oidc = new OpenIdConnectOptions();
        options.OidcProviders["Microsoft"].Configure(oidc);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.OidcProviders["Microsoft"].ProviderName, Is.EqualTo("Microsoft"));
            Assert.That(oidc.Authority, Is.EqualTo(MicrosoftOidcDefaults.BuildAuthority("contoso.onmicrosoft.com")));
        }
    }

    [Test]
    public void AddMicrosoftShouldSupportConfigureOverload()
    {
        var options = new AshlarOAuthOptions();

        options.AddMicrosoft("contoso.onmicrosoft.com", oidc => oidc.ClientId = "client");
        var oidc = new OpenIdConnectOptions();
        options.OidcProviders["Microsoft"].Configure(oidc);

        Assert.That(oidc.ClientId, Is.EqualTo("client"));
    }

    [Test]
    public void AddMicrosoftShouldSupportCustomProviderName()
    {
        var options = new AshlarOAuthOptions();

        options.AddMicrosoft("contoso.onmicrosoft.com", providerName: "Microsoft-Contoso");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.OidcProviders, Does.ContainKey("Microsoft-Contoso"));
            Assert.That(options.OidcProviders["Microsoft-Contoso"].ProviderName, Is.EqualTo("Microsoft-Contoso"));
        }
    }

    [Test]
    public void AddMicrosoftPersonalAccountsShouldRegisterConsumersAuthority()
    {
        var options = new AshlarOAuthOptions();

        options.AddMicrosoftPersonalAccounts();

        var oidc = new OpenIdConnectOptions();
        options.OidcProviders["MicrosoftPersonal"].Configure(oidc);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.OidcProviders["MicrosoftPersonal"].ProviderName, Is.EqualTo("MicrosoftPersonal"));
            Assert.That(options.OidcProviders["MicrosoftPersonal"].ProviderKeyMode, Is.EqualTo(AshlarOidcProviderKeyMode.IssuerAndSubject));
            Assert.That(oidc.Authority, Is.EqualTo(MicrosoftOidcDefaults.BuildSignInAuthority("consumers")));
        }
    }

    [Test]
    public void AddMicrosoftAnyAccountShouldRegisterCommonAuthority()
    {
        var options = new AshlarOAuthOptions();

        options.AddMicrosoftAnyAccount(providerName: "MicrosoftAll");

        var oidc = new OpenIdConnectOptions();
        options.OidcProviders["MicrosoftAll"].Configure(oidc);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.OidcProviders["MicrosoftAll"].ProviderName, Is.EqualTo("MicrosoftAll"));
            Assert.That(options.OidcProviders["MicrosoftAll"].ProviderKeyMode, Is.EqualTo(AshlarOidcProviderKeyMode.IssuerAndSubject));
            Assert.That(oidc.Authority, Is.EqualTo(MicrosoftOidcDefaults.BuildSignInAuthority("common")));
            Assert.That(oidc.TokenValidationParameters.IssuerValidator, Is.Not.Null);
        }
    }

    [Test]
    public void AddMicrosoftShouldUseUnqualifiedProviderKeyForExplicitTenantAuthority()
    {
        var options = new AshlarOAuthOptions();

        options.AddMicrosoft("contoso.onmicrosoft.com");

        Assert.That(options.OidcProviders["Microsoft"].ProviderKeyMode, Is.EqualTo(AshlarOidcProviderKeyMode.Subject));
    }

    [Test]
    public void AddMicrosoftShouldRegisterMicrosoftInvitationEmailPolicy()
    {
        var services = new ServiceCollection();
        services.AddAshlarOAuth(options => options.AddMicrosoft("contoso.onmicrosoft.com"));

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IOidcInvitationEmailMatchPolicy>(), Is.TypeOf<MicrosoftOidcInvitationEmailMatchPolicy>());
    }

    [Test]
    public void AddMicrosoftPersonalAccountsShouldUseStandardInvitationEmailPolicy()
    {
        var services = new ServiceCollection();
        services.AddAshlarOAuth(options => options.AddMicrosoftPersonalAccounts());

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IOidcInvitationEmailMatchPolicy>(), Is.TypeOf<StandardOidcVerifiedEmailMatchPolicy>());
    }

    [Test]
    public void AddMicrosoftShouldRejectMissingTenant()
    {
        var options = new AshlarOAuthOptions();

        Assert.Throws<ArgumentException>(() => options.AddMicrosoft(" "));
    }

    [TestCase("common")]
    [TestCase("organizations")]
    [TestCase("consumers")]
    public void AddMicrosoftShouldRejectSharedTenantSegments(string tenant)
    {
        var options = new AshlarOAuthOptions();

        Assert.Throws<ArgumentException>(() => options.AddMicrosoft(tenant));
    }

    [Test]
    public void AddAshlarOAuthShouldRejectDuplicateProviderNamesIgnoringCaseAndWhitespace()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddAshlarOAuth(options =>
        {
            options.AddOidcProvider("Google", _ => { });
            options.AddOidcProvider(" google ", _ => { });
        }));
    }

    private static OpenIdConnectOptions ConfigureGoogleOptions(IEnumerable<string> hostedDomains)
    {
        var options = new AshlarOAuthOptions();
        options.AddGoogle(hostedDomains);
        var oidc = new OpenIdConnectOptions();
        options.OidcProviders["Google"].Configure(oidc);
        return oidc;
    }

    private static RedirectContext CreateRedirectContext(OpenIdConnectOptions options)
    {
        var context = new RedirectContext(
            new DefaultHttpContext(),
            new AuthenticationScheme("Google", "Google", typeof(OpenIdConnectHandler)),
            options,
            new AuthenticationProperties())
        {
            ProtocolMessage = new OpenIdConnectMessage()
        };
        return context;
    }

    private static TokenValidatedContext CreateTokenValidatedContext(OpenIdConnectOptions options, string? hostedDomain)
    {
        var claims = new List<Claim> { new("sub", "subject") };
        if (hostedDomain != null)
        {
            claims.Add(new Claim("hd", hostedDomain));
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "oidc"));
        return new TokenValidatedContext(
            new DefaultHttpContext(),
            new AuthenticationScheme("Google", "Google", typeof(OpenIdConnectHandler)),
            options,
            principal,
            new AuthenticationProperties());
    }
}
