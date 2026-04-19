param(
  [string]$Version,
  [string]$InstallDir,
  [string]$BaseUrl,
  [switch]$NoPersistEnvironment
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoOwner = 'LATTIX-IO'
$repoName = 'sdk-rust-public'
$releaseApi = "https://api.github.com/repos/$repoOwner/$repoName/releases/latest"
$githubToken = if ($env:LATTIX_SDK_GITHUB_TOKEN) { $env:LATTIX_SDK_GITHUB_TOKEN } elseif ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { $env:GH_TOKEN }

function Get-ReleaseRequestHeaders {
  $headers = @{ 'User-Agent' = 'lattix-sdk-go-installer' }
  if ($githubToken) {
    $headers['Authorization'] = "Bearer $githubToken"
  }
  return $headers
}

function Get-ReleaseByTag {
  param([Parameter(Mandatory = $true)][string]$Tag)
  $headers = Get-ReleaseRequestHeaders
  return Invoke-RestMethod -Uri "https://api.github.com/repos/$repoOwner/$repoName/releases/tags/$Tag" -Headers $headers
}

function Get-AssetDownloadUrl {
  param(
    [Parameter(Mandatory = $true)][object]$Release,
    [Parameter(Mandatory = $true)][string]$AssetName
  )

  $asset = $Release.assets | Where-Object { $_.name -eq $AssetName } | Select-Object -First 1
  if (-not $asset) {
    throw "Could not resolve asset '$AssetName' for release '$($Release.tag_name)'."
  }

  if ($githubToken) {
    return [string]$asset.url
  }

  return [string]$asset.browser_download_url
}

function Get-LatestReleaseTag {
  $headers = Get-ReleaseRequestHeaders
  $release = Invoke-RestMethod -Uri $releaseApi -Headers $headers
  if (-not $release.tag_name) {
    throw 'Could not resolve the latest sdk-rust release tag.'
  }
  return [string]$release.tag_name
}

function Resolve-AssetName {
  $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
  switch ($arch) {
    'X64' { return 'sdk-rust-native-windows-x86_64.zip' }
    default { throw "Unsupported Windows architecture: $arch" }
  }
}

if (-not $BaseUrl -and $env:LATTIX_SDK_RUST_RELEASE_BASE_URL) {
  $BaseUrl = $env:LATTIX_SDK_RUST_RELEASE_BASE_URL
}

if (-not $Version) {
  $Version = Get-LatestReleaseTag
}

if (-not $InstallDir) {
  $InstallDir = Join-Path $HOME ".lattix/sdk-go/$Version"
}

$assetName = Resolve-AssetName
$downloadUrl = $null
$tempArchive = Join-Path ([System.IO.Path]::GetTempPath()) $assetName
$tempExtract = Join-Path ([System.IO.Path]::GetTempPath()) ("sdk-go-native-" + [guid]::NewGuid().ToString('N'))

if ($BaseUrl) {
  $downloadUrl = ($BaseUrl.TrimEnd('/')) + "/$Version/$assetName"
  Write-Host "Installing sdk-go native dependency from $downloadUrl"
  Invoke-WebRequest -Uri $downloadUrl -OutFile $tempArchive -Headers @{ 'User-Agent' = 'lattix-sdk-go-installer' }
} else {
  $release = Get-ReleaseByTag -Tag $Version
  $downloadUrl = Get-AssetDownloadUrl -Release $release -AssetName $assetName
  Write-Host "Installing sdk-go native dependency from $downloadUrl"
  $headers = Get-ReleaseRequestHeaders
  if ($githubToken) {
    $headers['Accept'] = 'application/octet-stream'
  }
  Invoke-WebRequest -Uri $downloadUrl -OutFile $tempArchive -Headers $headers
}

New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null
Expand-Archive -Path $tempArchive -DestinationPath $tempExtract -Force

$nativeRoot = Join-Path $tempExtract 'native'
if (-not (Test-Path $nativeRoot)) {
  throw "Downloaded archive did not contain the expected native/ directory."
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item (Join-Path $nativeRoot '*') $InstallDir -Recurse -Force

$dllPath = Join-Path $InstallDir 'sdk_rust.dll'
if (-not (Test-Path $dllPath)) {
  throw "Expected sdk_rust.dll under $InstallDir after extraction."
}

$activateScript = Join-Path $InstallDir 'activate-native.ps1'
@(
  "$env:LATTIX_SDK_RUST_LIB = '$dllPath'"
  "Write-Host 'LATTIX_SDK_RUST_LIB set to $dllPath'"
) | Set-Content -Path $activateScript -Encoding UTF8

$env:LATTIX_SDK_RUST_LIB = $dllPath
if (-not $NoPersistEnvironment) {
  [System.Environment]::SetEnvironmentVariable('LATTIX_SDK_RUST_LIB', $dllPath, 'User')
}

Write-Host "Installed native sdk-rust bundle to $InstallDir"
Write-Host "Current shell: LATTIX_SDK_RUST_LIB=$dllPath"
if ($NoPersistEnvironment) {
  Write-Host "User environment was not updated. Re-run this script without -NoPersistEnvironment or dot-source $activateScript in future shells."
} else {
  Write-Host 'User environment updated. Open a new shell if you want the persisted variable immediately.'
}
