param(
    [string] $Configuration = "Release",
    [string] $PackageOutputPath = (Join-Path (Join-Path $PSScriptRoot "..") "nupkg"),
    [switch] $SkipPack
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$packageOutputPath = [IO.Path]::GetFullPath($PackageOutputPath, $repoRoot)
$smokeRoot = Join-Path ([IO.Path]::GetTempPath()) "ashlar-package-consumption-smoke-$([Guid]::NewGuid().ToString('N'))"
$packagesPath = Join-Path $smokeRoot ".packages"
$nugetConfig = Join-Path $smokeRoot "nuget.config"

function Invoke-DotNet {
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $Arguments)

    Write-Output "dotnet $($Arguments -join ' ')"
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet command failed with exit code $LASTEXITCODE." }
}

$applicationPackages = @(
    "Ashlar",
    "Ashlar.AspNetCore",
    "Ashlar.Sqlite",
    "Ashlar.Postgres",
    "Ashlar.Passkeys",
    "Ashlar.Email.Smtp",
    "Ashlar.Observability",
    "Ashlar.Webhooks",
    "Ashlar.Redis"
)
$allPackages = $applicationPackages + "Ashlar.ProviderContracts" + "Ashlar.ProviderContractTests"

if (-not $SkipPack) {
    New-Item -ItemType Directory -Force -Path $packageOutputPath | Out-Null
    Invoke-DotNet pack (Join-Path $repoRoot "Ashlar.slnx") --configuration $Configuration --output $packageOutputPath
}

$contractPackage = Get-ChildItem $packageOutputPath -Filter "Ashlar.ProviderContractTests.*.nupkg" |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if ($null -eq $contractPackage -or
    $contractPackage.Name -notmatch '^Ashlar\.ProviderContractTests\.(?<version>\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\.nupkg$') {
    throw "Could not find a versioned Ashlar.ProviderContractTests package in '$packageOutputPath'."
}
$version = $Matches.version
foreach ($package in $allPackages) {
    if (-not (Test-Path (Join-Path $packageOutputPath "$package.$version.nupkg"))) {
        throw "Expected $package $version in '$packageOutputPath'."
    }
}
Write-Host "Testing Ashlar packages $version"

New-Item -ItemType Directory -Path $smokeRoot | Out-Null
$escapedPackagePath = [Security.SecurityElement]::Escape($packageOutputPath)
Set-Content $nugetConfig @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local-ashlar" value="$escapedPackagePath" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
"@

try {
    $appPath = Join-Path $smokeRoot "App"
    New-Item -ItemType Directory -Path $appPath | Out-Null
    $appReferences = ($applicationPackages | ForEach-Object { "    <PackageReference Include=`"$_`" Version=`"$version`" />" }) -join "`n"
    Set-Content (Join-Path $appPath "App.csproj") @"
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
  <ItemGroup>
$appReferences
  </ItemGroup>
  <Target Name="RejectProviderAuthoringCompileSurface" BeforeTargets="CoreCompile">
    <Error Condition="'@(ReferencePath->WithMetadataValue('Filename', 'Ashlar.ProviderContracts'))' != ''"
           Text="Ordinary consumers must not receive Ashlar.ProviderContracts as a compile reference." />
  </Target>
</Project>
"@
    Set-Content (Join-Path $appPath "Program.cs") @'
using Ashlar.OAuth.Providers.Google;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDataProtection();
builder.Services.AddAshlarIdentity();
builder.Services.AddAshlarAspNetCoreSessions();
builder.Services.AddAshlarSqlite("Data Source=:memory:");
builder.Services.AddAshlarPostgres("Host=localhost;Database=ashlar_smoke;Username=ashlar;Password=ashlar");
builder.Services.AddAshlarPasskeys();
builder.Services.AddAshlarSmtpEmailSender(options => options.Host = "localhost");
builder.Services.AddAshlarSecurityEventMetrics();
builder.Services.AddAshlarSecurityEventWebhooks();
builder.Services.AddAshlarOAuth(options => options.AddGoogle(oidc =>
{
    oidc.ClientId = "ashlar-smoke-client-id";
    oidc.ClientSecret = "ashlar-smoke-client-secret";
}));
builder.Services.AddAshlarRedisRateLimiting("localhost:6379",
    options => options.KeyPrefix = "package-smoke:ashlar:rate-limits");

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/", () => Results.Ok());
'@
    Invoke-DotNet restore $appPath --configfile $nugetConfig --packages $packagesPath
    Invoke-DotNet build $appPath --configuration $Configuration --no-restore
    $depsFile = Join-Path $appPath "bin/$Configuration/net10.0/App.deps.json"
    if (-not (Select-String $depsFile -Pattern 'Ashlar.ProviderContracts' -Quiet)) {
        throw "Ordinary consumers must receive Ashlar.ProviderContracts as a runtime dependency."
    }

    $providerPath = Join-Path $smokeRoot "Provider"
    New-Item -ItemType Directory -Path $providerPath | Out-Null
    Set-Content (Join-Path $providerPath "Provider.csproj") @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
  <ItemGroup><PackageReference Include="Ashlar.ProviderContracts" Version="$version" /></ItemGroup>
</Project>
"@
    Set-Content (Join-Path $providerPath "Provider.cs") @'
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.ProviderContracts.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

internal static class CompositionSmoke
{
    public static void Compose(IServiceCollection services)
    {
        services.AddAshlarProviderScoped<CustomTransactionProvider, object>("Custom", _ => new());
        services.AddAshlarDurableTransactionProvider<CustomTransactionProvider>("Custom");
        services.AddAshlarDurableTransactionParticipant<object>();
    }
}

internal sealed class CustomTransactionProvider : IAshlarTransactionProvider
{
    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) =>
        throw new NotSupportedException();
}
'@
    Invoke-DotNet restore $providerPath --configfile $nugetConfig --packages $packagesPath
    Invoke-DotNet build $providerPath --configuration $Configuration --no-restore

    $testsPath = Join-Path $smokeRoot "External.Provider.Tests"
    New-Item -ItemType Directory -Path $testsPath | Out-Null
    Set-Content (Join-Path $testsPath "External.Provider.Tests.csproj") @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <OutputType>Exe</OutputType>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsTestProject>true</IsTestProject>
    <UseMicrosoftTestingPlatformRunner>true</UseMicrosoftTestingPlatformRunner>
    <EnableNUnitRunner>true</EnableNUnitRunner>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="18.8.1" />
    <PackageReference Include="NUnit" Version="4.6.1" />
    <PackageReference Include="NUnit3TestAdapter" Version="6.2.0" />
    <PackageReference Include="Ashlar.ProviderContractTests" Version="$version" />
  </ItemGroup>
</Project>
"@
    Set-Content (Join-Path $testsPath "Contracts.cs") @'
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Authentication;
using Ashlar.Identity.Models.Bootstrap;
using Ashlar.ProviderContractTests.Identity;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

[TestFixture]
public sealed class ExternalBootstrapContracts : BootstrapStateRepositoryContractTests
{
    protected override Task<IServiceProvider> CreateInitializedServiceProviderAsync() =>
        Task.FromResult<IServiceProvider>(new ServiceCollection()
            .AddSingleton<IUserRepository, Users>()
            .AddSingleton<IBootstrapStateRepository, BootstrapState>()
            .BuildServiceProvider());
}

internal sealed class BootstrapState : IBootstrapStateRepository
{
    private bool _initialized;
    public Task<BootstrapStatus> GetBootstrapStatusAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_initialized ? BootstrapStatus.Initialized : BootstrapStatus.Uninitialized);
    public Task<bool> MarkAsInitializedAsync(Guid userId, DateTimeOffset initializedAt, CancellationToken cancellationToken = default)
    {
        var changed = !_initialized;
        _initialized = true;
        return Task.FromResult(changed);
    }
}

internal sealed class Users : IUserRepository
{
    public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
    public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
    public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
}
'@
    Invoke-DotNet restore $testsPath --configfile $nugetConfig --packages $packagesPath
    Invoke-DotNet test $testsPath --configuration $Configuration --no-restore -- --minimum-expected-tests 3

    Write-Host "Package consumption smoke test passed."
}
finally {
    if (Test-Path $smokeRoot) { Remove-Item -LiteralPath $smokeRoot -Recurse -Force }
}
