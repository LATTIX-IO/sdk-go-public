param(
  [switch]$Fast
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-OsPlatform {
  param([System.Runtime.InteropServices.OSPlatform]$Platform)

  return [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform($Platform)
}

$script:IsWindowsPlatform = Test-OsPlatform ([System.Runtime.InteropServices.OSPlatform]::Windows)
$script:IsMacOSPlatform = Test-OsPlatform ([System.Runtime.InteropServices.OSPlatform]::OSX)

Write-Host "sdk-go local quality gate"

function Get-Tool {
  param([string]$Name)

  $command = Get-Command $Name -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }
  $command = Get-Command "$Name.exe" -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }
  return $null
}

function Get-TrivyVersion {
  param([string]$ToolPath)

  $versionOutput = (& $ToolPath --version 2>$null) -join [Environment]::NewLine
  if (-not $versionOutput) {
    $versionOutput = (& $ToolPath version 2>$null) -join [Environment]::NewLine
  }

  if ($versionOutput -match '(?<version>\d+\.\d+\.\d+)') {
    return $Matches.version
  }

  return $null
}

function Assert-SafeTrivyVersion {
  param([string]$ToolPath)

  $version = Get-TrivyVersion -ToolPath $ToolPath
  if (-not $version) {
    throw "Refusing to run Trivy because its version could not be determined. Install Trivy v0.69.3 or v0.69.2."
  }

  if ($version -in @('0.69.4', '0.69.5', '0.69.6')) {
    throw "Refusing to run compromised Trivy $version (GHSA-69fq-xp46-6x23 / CVE-2026-33634). Install Trivy v0.69.3 or v0.69.2."
  }
}

function Invoke-OptionalTool {
  param(
    [string]$Name,
    [string]$Description,
    [string[]]$Arguments
  )

  $tool = Get-Tool $Name
  if (-not $tool) {
    Write-Host " - Skipping $Description (missing $Name)"
    return
  }

  if ($Name -eq 'trivy') {
    Assert-SafeTrivyVersion -ToolPath $tool
  }

  Write-Host " - $Description"
  & $tool @Arguments
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}

$go = Get-Tool go
if (-not $go) {
  throw "go is required for sdk-go quality checks."
}

$cargo = Get-Tool cargo
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$rustRepo = Join-Path $repoRoot "../sdk-rust"
$builtSdkRust = $false

function Prepare-NativeRustBindings {
  if ($env:LATTIX_SDK_RUST_LIB -and (Test-Path $env:LATTIX_SDK_RUST_LIB)) {
    return $true
  }

  if ($env:LATTIX_SDK_RUST_LIB) {
    Write-Host " - Ignoring stale LATTIX_SDK_RUST_LIB path: $env:LATTIX_SDK_RUST_LIB"
    Remove-Item Env:LATTIX_SDK_RUST_LIB -ErrorAction SilentlyContinue
  }

  if (-not (Test-Path $rustRepo) -or -not $cargo) {
    return $false
  }

  Write-Host " - Building sibling sdk-rust native library for rustbindings checks"
  Push-Location $rustRepo
  try {
    & $cargo build --release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  }
  finally {
    Pop-Location
  }

  $script:builtSdkRust = $true

  if ($script:IsWindowsPlatform) {
    $env:LATTIX_SDK_RUST_LIB = (Join-Path $rustRepo "target/release/sdk_rust.dll")
  } elseif ($script:IsMacOSPlatform) {
    $env:CGO_CFLAGS = @($env:CGO_CFLAGS, "-I$(Join-Path $rustRepo 'include')") -join ' '
    $env:CGO_LDFLAGS = @($env:CGO_LDFLAGS, "-L$(Join-Path $rustRepo 'target/release')") -join ' '
    $env:DYLD_LIBRARY_PATH = @((Join-Path $rustRepo 'target/release'), $env:DYLD_LIBRARY_PATH) -ne '' -join ':'
  } else {
    $env:CGO_CFLAGS = @($env:CGO_CFLAGS, "-I$(Join-Path $rustRepo 'include')") -join ' '
    $env:CGO_LDFLAGS = @($env:CGO_LDFLAGS, "-L$(Join-Path $rustRepo 'target/release')") -join ' '
    $env:LD_LIBRARY_PATH = @((Join-Path $rustRepo 'target/release'), $env:LD_LIBRARY_PATH) -ne '' -join ':'
  }

  return $true
}

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$goFiles = Get-ChildItem -Path $repoRoot -Recurse -Filter *.go -File | Where-Object { $_.FullName -notmatch '\\.git\\' }

try {
  Write-Host "1) Apply automated fixes"
  $goimports = Get-Tool goimports
  if ($goFiles.Count -gt 0) {
    if ($goimports) {
      & $goimports -w $goFiles.FullName
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
      & gofmt -w $goFiles.FullName
      if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
  }
  & $go mod tidy
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  Write-Host "2) Lint and correctness"
  if ($goFiles.Count -gt 0) {
    & gofmt -w $goFiles.FullName
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $unformatted = & gofmt -l $goFiles.FullName
    if ($unformatted) {
      throw "gofmt reported unformatted files after fixes.`n$unformatted"
    }
  }
  & $go vet ./...
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  Invoke-OptionalTool -Name staticcheck -Description "Static analysis via staticcheck" -Arguments @("./...")

  Write-Host "3) Security scans"
  Invoke-OptionalTool -Name semgrep -Description "SAST via Semgrep" -Arguments @("--config=auto", "--exclude", ".git", "--exclude", "vendor", "--exclude", "dist", "--exclude", ".venv", ".")
  Invoke-OptionalTool -Name gitleaks -Description "Secret scanning via Gitleaks" -Arguments @("detect", "--source", ".", "--no-git", "--redact")
  Invoke-OptionalTool -Name govulncheck -Description "Go vulnerability scan via govulncheck" -Arguments @("./...")
  if (-not $Fast) {
    Invoke-OptionalTool -Name gosec -Description "Go SAST via gosec" -Arguments @("./...")
    Invoke-OptionalTool -Name trivy -Description "Filesystem security scan via Trivy" -Arguments @("fs", "--scanners", "vuln,misconfig,secret", "--severity", "HIGH,CRITICAL", "--exit-code", "1", ".")
  } else {
    Write-Host " - Fast mode: skipping gosec and Trivy"
  }

  Write-Host "4) Tests"
  & $go test ./...
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  if (-not $Fast -and (Prepare-NativeRustBindings)) {
    & $go test ./... -tags rustbindings
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  } else {
    Write-Host " - Skipping rustbindings tests (fast mode or native sdk-rust unavailable)"
  }

  Write-Host "5) Build"
  & $go build ./...
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  if (-not $Fast -and ($env:LATTIX_SDK_RUST_LIB -or $env:CGO_CFLAGS)) {
  & $go build -tags rustbindings ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  } else {
    Write-Host " - Skipping rustbindings build (fast mode or native sdk-rust unavailable)"
  }

  Write-Host "All checks passed."
}
finally {
  Write-Host "6) Cleanup"
  & $go clean -cache -testcache *> $null
  if ($builtSdkRust -and $cargo) {
    Push-Location $rustRepo
    try {
      & $cargo clean *> $null
    }
    finally {
      Pop-Location
    }
  }
}