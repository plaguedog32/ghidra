# Dot-source before Cargo when Windows native build helpers need the SDK.
# This changes only the current PowerShell process environment.
param([ValidateSet('x64', 'arm64')][string]$Architecture = 'x64')

if ($env:OS -ne 'Windows_NT') { return }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $nativeCargoRoot = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
    if (Test-Path -LiteralPath (Join-Path $nativeCargoRoot 'bin\cargo.exe')) { $env:PATH = (Join-Path $nativeCargoRoot 'bin') + ';' + $env:PATH }
}
$vsLocator = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vsLocator)) { throw 'Install the Visual Studio C++ build tools and Windows SDK.' }
$env:PATH = (Split-Path -Parent $vsLocator) + ';' + $env:PATH
$nativeInstallations = & $vsLocator -all -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json | ConvertFrom-Json
if (-not $nativeInstallations) { throw 'Visual Studio C++ tools were not found.' }
# Keep a configured MSVC compiler and its headers/libraries in the same installation.
$nativeInstallation = $nativeInstallations | Where-Object {
    $env:CC -and $env:CC.StartsWith($_.installationPath + '\', [StringComparison]::OrdinalIgnoreCase)
} | Select-Object -First 1
if (-not $nativeInstallation) { $nativeInstallation = $nativeInstallations | Select-Object -First 1 }
$nativeDevModule = Join-Path $nativeInstallation.installationPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
Import-Module $nativeDevModule -ErrorAction Stop
Enter-VsDevShell -VsInstallPath $nativeInstallation.installationPath -SkipAutomaticLocation -DevCmdArguments "-arch=$Architecture -host_arch=x64" -ErrorAction Stop
