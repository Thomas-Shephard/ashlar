using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Ashlar.OAuth.Providers.Apple;
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
            Assert.That(services.Any(d => d.ServiceType == typeof(AshlarExternalCredentialAuthenticationService)), Is.True);
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
    public void AddAppleShouldRegisterExpectedProviderSchemeAndDefaults()
    {
        var options = new AshlarOAuthOptions();

        options.AddApple();

        var provider = options.OidcProviders["Apple"];
        var oidc = new OpenIdConnectOptions();
        provider.Configure(oidc);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.ProviderName, Is.EqualTo("Apple"));
            Assert.That(provider.SchemeName, Is.EqualTo("Apple"));
            Assert.That(provider.ProviderKeyMode, Is.EqualTo(AshlarOidcProviderKeyMode.Subject));
            Assert.That(provider.GetClaimsFromUserInfoEndpoint, Is.False);
            Assert.That(oidc.Authority, Is.EqualTo(AppleOidcDefaults.Authority));
            Assert.That(oidc.ResponseType, Is.EqualTo("code"));
            Assert.That(oidc.ResponseMode, Is.EqualTo(OpenIdConnectResponseMode.FormPost));
            Assert.That(oidc.Scope, Does.Contain("openid"));
            Assert.That(oidc.Scope, Does.Contain("email"));
            Assert.That(oidc.Scope, Does.Contain("name"));
            Assert.That(oidc.Scope, Does.Not.Contain("profile"));
        }
    }

    [Test]
    public void AddAppleShouldAllowCallerConfigurationToOverrideAndExtendOidcOptions()
    {
        var options = new AshlarOAuthOptions();

        options.AddApple(oidc =>
        {
            oidc.Authority = "https://apple.example.test";
            oidc.ClientId = "client";
            oidc.Scope.Add("custom");
        });
        var provider = options.OidcProviders["Apple"];
        var oidc = new OpenIdConnectOptions();
        provider.Configure(oidc);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(oidc.Authority, Is.EqualTo("https://apple.example.test"));
            Assert.That(oidc.ClientId, Is.EqualTo("client"));
            Assert.That(oidc.Scope, Does.Contain("custom"));
        }
    }

    [Test]
    public void AddAppleShouldSupportCustomProviderName()
    {
        var options = new AshlarOAuthOptions();

        options.AddApple(providerName: "Apple-Work");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.OidcProviders, Does.ContainKey("Apple-Work"));
            Assert.That(options.OidcProviders["Apple-Work"].ProviderName, Is.EqualTo("Apple-Work"));
            Assert.That(options.OidcProviders["Apple-Work"].SchemeName, Is.EqualTo("Apple-Work"));
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
    public void AddOidcProviderShouldSupportUserInfoEndpointOptOut()
    {
        var options = new AshlarOAuthOptions();

        options.AddOidcProvider("NoUserInfo", AshlarOidcProviderKeyMode.Subject, _ => { }, getClaimsFromUserInfoEndpoint: false);

        Assert.That(options.OidcProviders["NoUserInfo"].GetClaimsFromUserInfoEndpoint, Is.False);
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
    public void AddAshlarOAuthShouldConfigureAppleRemoteHandlerForProviderCallback()
    {
        var services = new ServiceCollection();

        services.AddAshlarOAuth(options => options.AddApple(oidc =>
        {
            oidc.ClientId = "client";
            oidc.ClientSecret = "secret";
        }));

        using var provider = services.BuildServiceProvider();
        var oidcOptions = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Apple");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(oidcOptions.SignInScheme, Is.EqualTo("Ashlar.OAuth.External"));
            Assert.That(oidcOptions.CallbackPath.Value, Is.EqualTo("/signin-oidc/Apple"));
            Assert.That(oidcOptions.SaveTokens, Is.False);
            Assert.That(oidcOptions.GetClaimsFromUserInfoEndpoint, Is.False);
            Assert.That(oidcOptions.Authority, Is.EqualTo(AppleOidcDefaults.Authority));
            Assert.That(oidcOptions.ResponseType, Is.EqualTo("code"));
            Assert.That(oidcOptions.ResponseMode, Is.EqualTo(OpenIdConnectResponseMode.FormPost));
        }
    }

    [Test]
    public async Task AddAppleShouldMapFirstAuthorizationUserNameClaimsAndChainTokenValidatedEvent()
    {
        var called = false;
        var oidc = ConfigureAppleOptions(options =>
        {
            options.Events.OnTokenValidated = _ =>
            {
                called = true;
                return Task.CompletedTask;
            };
        });
        var context = CreateAppleTokenValidatedContext(oidc, """{"name":{"firstName":" Ada ","lastName":" Lovelace "},"email":"ignored@example.com"}""");

        await oidc.Events.OnTokenValidated(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(called, Is.True);
            Assert.That(context.Principal?.FindFirstValue("given_name"), Is.EqualTo("Ada"));
            Assert.That(context.Principal?.FindFirstValue("family_name"), Is.EqualTo("Lovelace"));
            Assert.That(context.Principal?.FindFirstValue("name"), Is.EqualTo("Ada Lovelace"));
            Assert.That(context.Principal?.Claims.Where(claim => claim.Type == "email").Select(claim => claim.Value), Is.EqualTo(["id-token@example.com"]));
        }
    }

    [Test]
    public async Task AddAppleShouldMapPartialFirstAuthorizationUserNameClaims()
    {
        var oidc = ConfigureAppleOptions();
        var context = CreateAppleTokenValidatedContext(oidc, """{"name":{"lastName":" Hopper "}}""");

        await oidc.Events.OnTokenValidated(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Principal?.FindFirstValue("given_name"), Is.Null);
            Assert.That(context.Principal?.FindFirstValue("family_name"), Is.EqualTo("Hopper"));
            Assert.That(context.Principal?.FindFirstValue("name"), Is.EqualTo("Hopper"));
        }
    }

    [Test]
    public async Task AddAppleShouldMapGivenNameOnlyFirstAuthorizationUserNameClaim()
    {
        var oidc = ConfigureAppleOptions();
        var context = CreateAppleTokenValidatedContext(oidc, """{"name":{"firstName":" Ada "}}""");

        await oidc.Events.OnTokenValidated(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Principal?.FindFirstValue("given_name"), Is.EqualTo("Ada"));
            Assert.That(context.Principal?.FindFirstValue("family_name"), Is.Null);
            Assert.That(context.Principal?.FindFirstValue("name"), Is.EqualTo("Ada"));
        }
    }

    [Test]
    public async Task AddAppleShouldPreserveExistingNameClaims()
    {
        var oidc = ConfigureAppleOptions();
        var context = CreateAppleTokenValidatedContext(
            oidc,
            """{"name":{"firstName":"New","lastName":"Person"}}""",
            new Claim("given_name", "Existing"),
            new Claim("family_name", "Claims"),
            new Claim("name", "Existing Claims"));

        await oidc.Events.OnTokenValidated(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Principal?.FindFirstValue("given_name"), Is.EqualTo("Existing"));
            Assert.That(context.Principal?.FindFirstValue("family_name"), Is.EqualTo("Claims"));
            Assert.That(context.Principal?.FindFirstValue("name"), Is.EqualTo("Existing Claims"));
        }
    }

    [TestCase(null)]
    [TestCase(" ")]
    [TestCase("not-json")]
    [TestCase("{}")]
    [TestCase("""{"name":"Ada"}""")]
    [TestCase("""{"name":{"firstName":" ","lastName":" "}}""")]
    [TestCase("""{"name":{"firstName":42,"lastName":false}}""")]
    public async Task AddAppleShouldIgnoreMissingOrInvalidUserNamePayload(string? userJson)
    {
        var oidc = ConfigureAppleOptions();
        var context = CreateAppleTokenValidatedContext(oidc, userJson);

        await oidc.Events.OnTokenValidated(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Principal?.FindFirstValue("given_name"), Is.Null);
            Assert.That(context.Principal?.FindFirstValue("family_name"), Is.Null);
            Assert.That(context.Principal?.FindFirstValue("name"), Is.Null);
        }
    }

    [Test]
    public async Task AddAppleShouldIgnoreUserNamePayloadWhenPrincipalIsMissing()
    {
        var oidc = ConfigureAppleOptions();
        var context = CreateAppleTokenValidatedContext(oidc, """{"name":{"firstName":"Ada"}}""");
        context.Principal = null!;

        Assert.DoesNotThrowAsync(async () => await oidc.Events.OnTokenValidated(context));

        Assert.That(context.Principal, Is.Null);
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

    [Test]
    public void AddAppleShouldKeepDuplicateProviderNameBehaviorConsistent()
    {
        var options = new AshlarOAuthOptions();

        options.AddApple();

        Assert.Throws<ArgumentException>(() => options.AddApple(providerName: " apple "));
    }

    private static OpenIdConnectOptions ConfigureGoogleOptions(IEnumerable<string> hostedDomains)
    {
        var options = new AshlarOAuthOptions();
        options.AddGoogle(hostedDomains);
        var oidc = new OpenIdConnectOptions();
        options.OidcProviders["Google"].Configure(oidc);
        return oidc;
    }

    private static OpenIdConnectOptions ConfigureAppleOptions(Action<OpenIdConnectOptions>? configure = null)
    {
        var options = new AshlarOAuthOptions();
        options.AddApple(configure);
        var oidc = new OpenIdConnectOptions();
        options.OidcProviders["Apple"].Configure(oidc);
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

    private static TokenValidatedContext CreateAppleTokenValidatedContext(OpenIdConnectOptions options, string? userJson, params Claim[] claims)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "apple-subject"),
            new Claim("email", "id-token@example.com"),
            ..claims
        ], "oidc"));
        var context = new TokenValidatedContext(
            new DefaultHttpContext(),
            new AuthenticationScheme("Apple", "Apple", typeof(OpenIdConnectHandler)),
            options,
            principal,
            new AuthenticationProperties())
        {
            ProtocolMessage = new OpenIdConnectMessage()
        };

        if (userJson != null)
        {
            context.ProtocolMessage.SetParameter("user", userJson);
        }

        return context;
    }
}
