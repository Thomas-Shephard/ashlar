using Ashlar.Sample.AspNetCore;
using Ashlar.Sample.AspNetCore.Endpoints;
using Ashlar.Sample.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

var postgresStartup = await DevelopmentPostgresStartup.ConfigureAsync(builder);

builder.Services.AddSampleServices(builder.Configuration, postgresStartup);

var app = builder.Build();

SampleDevelopmentSafetyWarnings.LogStartupWarnings(app.Services);

await app.Services.InitializeAshlarPostgresSchemaAsync();
await SampleSchemaInitializer.InitializeAsync(app.Services);

app.UseStaticFiles();
app.UseAshlarRequireIpAddress();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapHomeEndpoints();
app.MapBootstrapEndpoints();
app.MapAuthEndpoints();
app.MapAccountEndpoints();
app.MapPasskeyEndpoints();
app.MapMfaEndpoints();
app.MapSessionEndpoints();
app.MapInvitationEndpoints();
app.MapGoogleOidcEndpoints();
app.MapGitHubOAuthEndpoints();
app.MapAdminEndpoints();

await app.RunAsync();
