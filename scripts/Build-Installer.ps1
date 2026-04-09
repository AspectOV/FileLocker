param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$RuntimeIdentifier = "win-x64",
    [string]$NsisPath
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$projectDir = Join-Path $repoRoot "FileLocker"
$projectPath = Join-Path $projectDir "FileLocker.csproj"
$installerScript = Join-Path $repoRoot "installer\\FileLocker.nsi"
$publishDir = Join-Path $repoRoot "artifacts\\nsis\\publish"
$outputDir = Join-Path $repoRoot "artifacts\\nsis"

[xml]$projectXml = Get-Content -Raw $projectPath
$targetFramework = $projectXml.Project.PropertyGroup.TargetFramework | Select-Object -First 1
$version = @(
    $projectXml.Project.PropertyGroup.Version | Select-Object -First 1
    $projectXml.Project.PropertyGroup.FileVersion | Select-Object -First 1
    $projectXml.Project.PropertyGroup.VersionPrefix | Select-Object -First 1
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1

if (-not $targetFramework) {
    throw "TargetFramework was not found in $projectPath."
}

if (-not $version) {
    throw "Version metadata was not found in $projectPath."
}

if (-not $NsisPath) {
    $candidatePaths = @(
        (Get-Command makensis.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        "C:\\Program Files (x86)\\NSIS\\makensis.exe",
        "C:\\Program Files\\NSIS\\makensis.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }

    $NsisPath = $candidatePaths | Select-Object -First 1
}

if (-not $NsisPath) {
    throw "makensis.exe was not found. Install NSIS or pass -NsisPath."
}

if (-not (Test-Path $NsisPath)) {
    throw "makensis.exe was not found at '$NsisPath'."
}

if (Test-Path $publishDir) {
    Remove-Item -Recurse -Force $publishDir
}

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Write-Host "Publishing unpackaged app..."
dotnet publish $projectPath `
    -c $Configuration `
    -r $RuntimeIdentifier `
    --self-contained true `
    /p:PublishSingleFile=false `
    /p:PublishTrimmed=false `
    -o $publishDir

if (-not (Test-Path (Join-Path $publishDir "FileLocker.exe"))) {
    throw "Expected publish output was not found at $publishDir."
}

$requiredPublishFiles = @(
    "App.xbf",
    "MainWindow.xbf",
    "FileLocker.pri",
    "Themes\\Styles.xbf",
    "Assets\\StoreLogo.png"
)

$missingPublishFiles = $requiredPublishFiles | Where-Object {
    -not (Test-Path (Join-Path $publishDir $_))
}

if ($missingPublishFiles.Count -gt 0) {
    throw "Publish output is incomplete. Missing required files: $($missingPublishFiles -join ', ')"
}

Write-Host "Building NSIS installer..."
& $NsisPath `
    "/DAPP_VERSION=$version" `
    "/DAPP_FILE_VERSION=$version" `
    "/DPUBLISH_DIR=$publishDir" `
    "/DOUTPUT_DIR=$outputDir" `
    $installerScript

if ($LASTEXITCODE -ne 0) {
    throw "makensis.exe failed with exit code $LASTEXITCODE."
}

$installerPath = Join-Path $outputDir "FileLocker-Setup-$version.exe"
Write-Host ""
Write-Host "Installer ready:"
Write-Host $installerPath
