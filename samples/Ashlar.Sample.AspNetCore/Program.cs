using Ashlar.Sample.AspNetCore;
using Ashlar.Sample.AspNetCore.Endpoints;
using Ashlar.Sample.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

var postgresStartup = await DevelopmentPostgresStartup.ConfigureAsync(builder);

builder.Services.AddSampleServices(builder.Configuration, postgresStartup);

var app = builder.Build();

await app.Services.InitializeAshlarPostgresSchemaAsync();

app.UseAshlarRequireIpAddress();
app.UseAuthentication();
app.UseAuthorization();

app.MapHomeEndpoints();
app.MapBootstrapEndpoints();
app.MapAuthEndpoints();
app.MapMfaEndpoints();
app.MapInvitationEndpoints();
app.MapAdminEndpoints();

await app.RunAsync();
