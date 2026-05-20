param(
    [string] $Configuration = "Release",
    [string] $PackageOutputPath = (Join-Path (Join-Path $PSScriptRoot "..") "nupkg"),
    [string] $SmokeRoot = (Join-Path ([System.IO.Path]::GetTempPath()) "ashlar-package-consumption-smoke"),
    [switch] $SkipPack
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$solutionPath = Join-Path $repoRoot "Ashlar.slnx"
$packageOutputFullPath = if ([System.IO.Path]::IsPathRooted($PackageOutputPath)) {
    [System.IO.Path]::GetFullPath($PackageOutputPath)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $PackageOutputPath))
}
$smokeRootFullPath = if ([System.IO.Path]::IsPathRooted($SmokeRoot)) {
    [System.IO.Path]::GetFullPath($SmokeRoot)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $repoRoot $SmokeRoot))
}

$packageIds = @(
    "Ashlar",
    "Ashlar.AspNetCore",
    "Ashlar.Sqlite",
    "Ashlar.Postgres",
    "Ashlar.Passkeys",
    "Ashlar.Email.Smtp"
)

function Invoke-DotNet {
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $Arguments)

    Write-Output "dotnet $($Arguments -join ' ')"
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet command failed with exit code $LASTEXITCODE."
    }
}

function Get-PackageVersion {
    param([string] $PackageId)

    $packageNamePattern = "^$([regex]::Escape($PackageId))\.(?<version>\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\.nupkg$"
    $packages = @(Get-ChildItem -Path $packageOutputFullPath -Filter "*.nupkg" |
        Where-Object { $_.Name -match $packageNamePattern } |
        Sort-Object LastWriteTimeUtc -Descending)

    if ($packages.Count -eq 0) {
        throw "Expected package '$PackageId' in '$packageOutputFullPath', but no .nupkg was found."
    }

    $fileName = $packages[0].Name
    if ($fileName -notmatch $packageNamePattern) {
        throw "Could not infer package version from '$fileName'."
    }

    return $Matches["version"]
}

if (-not $SkipPack) {
    New-Item -ItemType Directory -Force -Path $packageOutputFullPath | Out-Null
    Invoke-DotNet pack $solutionPath --configuration $Configuration --output $packageOutputFullPath
}

if (-not (Test-Path $packageOutputFullPath)) {
    throw "Package output path '$packageOutputFullPath' does not exist. Run dotnet pack first or omit -SkipPack."
}

$packageVersions = @{}
foreach ($packageId in $packageIds) {
    $packageVersions[$packageId] = Get-PackageVersion $packageId
    Write-Host "Using $packageId $($packageVersions[$packageId])"
}

if (Test-Path $smokeRootFullPath) {
    Remove-Item -LiteralPath $smokeRootFullPath -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $smokeRootFullPath | Out-Null

$smokeProjectPath = Join-Path $smokeRootFullPath "Ashlar.PackageSmoke"
Invoke-DotNet new web --framework net10.0 --output $smokeProjectPath --no-restore

$escapedPackageOutputPath = [System.Security.SecurityElement]::Escape($packageOutputFullPath)
$nugetConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local-ashlar" value="$escapedPackageOutputPath" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
"@
Set-Content -Path (Join-Path $smokeProjectPath "nuget.config") -Value $nugetConfig -Encoding utf8

$projectFile = Join-Path $smokeProjectPath "Ashlar.PackageSmoke.csproj"
[xml] $projectXml = Get-Content $projectFile
$itemGroup = $projectXml.CreateElement("ItemGroup")
foreach ($packageId in $packageIds) {
    $packageReference = $projectXml.CreateElement("PackageReference")
    $packageReference.SetAttribute("Include", $packageId)
    $packageReference.SetAttribute("Version", $packageVersions[$packageId])
    [void] $itemGroup.AppendChild($packageReference)
}

[void] $projectXml.Project.AppendChild($itemGroup)
$projectXml.Save($projectFile)

$program = @'
var builder = WebApplication.CreateBuilder(args);

// Compile one representative registration per package to catch restore, asset, dependency, and public API breaks.
builder.Services.AddDataProtection();
builder.Services.AddAshlarIdentity();
builder.Services.AddAshlarAspNetCoreSessions();
builder.Services.AddAshlarSqlite("Data Source=:memory:");
builder.Services.AddAshlarPostgres("Host=localhost;Database=ashlar_smoke;Username=ashlar;Password=ashlar");
builder.Services.AddAshlarPasskeys();
builder.Services.AddAshlarSmtpEmailSender(options =>
{
    options.Host = "localhost";
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/", () => Results.Ok("Ashlar package consumption smoke test"));

return 0;
'@
Set-Content -Path (Join-Path $smokeProjectPath "Program.cs") -Value $program -Encoding utf8

Invoke-DotNet restore $smokeProjectPath --configfile (Join-Path $smokeProjectPath "nuget.config")
Invoke-DotNet build $smokeProjectPath --configuration $Configuration --no-restore

Write-Host "Package consumption smoke test passed."
