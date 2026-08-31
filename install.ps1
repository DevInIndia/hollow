# Install a hollow binary on Windows. No Go toolchain, no compiler.
#
#   irm https://raw.githubusercontent.com/DevInIndia/hollow/main/install.ps1 | iex
#
# Or, to read it first:
#
#   irm https://raw.githubusercontent.com/DevInIndia/hollow/main/install.ps1 -OutFile install.ps1
#   notepad install.ps1
#   .\install.ps1
#
# Environment:
#   HOLLOW_VERSION       release tag to install, or "latest" (the default)
#   HOLLOW_INSTALL_DIR   where the binary goes (default $env:LOCALAPPDATA\hollow\bin)
#
# The binary is checked against the SHA256SUMS published with the same release
# before it is installed, and a mismatch installs nothing.
#
# Written against the same release layout install.sh uses, but not executed:
# there is no PowerShell on the machine this was developed on. The logic is a
# transcription of the shell script, which is tested.

$ErrorActionPreference = 'Stop'

$repo = 'DevInIndia/hollow'
$version = if ($env:HOLLOW_VERSION) { $env:HOLLOW_VERSION } else { 'latest' }
$installDir = if ($env:HOLLOW_INSTALL_DIR) { $env:HOLLOW_INSTALL_DIR } else { "$env:LOCALAPPDATA\hollow\bin" }

# Windows PowerShell 5.1 still defaults to TLS 1.0 for Invoke-WebRequest, which
# github.com refuses. PowerShell 7 negotiates properly and the property is
# deprecated there, so only touch it on the old one.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# windows/amd64 is the only published Windows target. Checked rather than
# assumed, so an ARM64 machine gets told what is wrong instead of downloading a
# 404 page and finding no checksum row for it.
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne 'AMD64') {
    throw @"
no published binary for windows/$arch.
  Published: linux/amd64, linux/arm64, darwin/arm64, windows/amd64.
  For windows/$arch, build from source with a Go toolchain:
    git clone https://github.com/$repo.git; cd hollow; go build ./cmd/hollow
"@
}

$asset = 'hollow-windows-amd64.exe'

# "latest" is a permanent GitHub redirect to the newest release, so the common
# path never names a version and never goes stale.
$base = if ($version -eq 'latest') {
    "https://github.com/$repo/releases/latest/download"
} else {
    "https://github.com/$repo/releases/download/$version"
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("hollow-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    Write-Host "hollow: fetching $asset ($version)"

    # -UseBasicParsing keeps 5.1 from routing the body through the Internet
    # Explorer engine, which is both slow and absent on Server Core.
    Invoke-WebRequest -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset) -UseBasicParsing
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS') -UseBasicParsing

    # The sums file carries bare filenames, so the asset name identifies its row.
    $want = $null
    foreach ($line in Get-Content (Join-Path $tmp 'SHA256SUMS')) {
        $parts = $line -split '\s+', 2
        if ($parts.Length -eq 2 -and $parts[1].Trim() -eq $asset) {
            $want = $parts[0]
            break
        }
    }
    if (-not $want) {
        throw "SHA256SUMS from $version has no entry for $asset"
    }

    # Get-FileHash returns upper case and sha256sum wrote lower case. PowerShell
    # string comparison is case insensitive by default, but relying on that here
    # would make this line quietly wrong the day someone reaches for -cne.
    $got = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $asset)).Hash.ToLower()
    if ($want.ToLower() -ne $got) {
        throw @"
checksum mismatch for $asset. Nothing was installed.
  expected $want
  actual   $got
"@
    }
    Write-Host "hollow: sha256 verified"

    # LOCALAPPDATA rather than Program Files, so this never needs an elevated
    # prompt.
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Move-Item -Force -Path (Join-Path $tmp $asset) -Destination (Join-Path $installDir 'hollow.exe')

    Write-Host "hollow: installed $installDir\hollow.exe"
    Write-Host ""

    if (($env:PATH -split ';') -notcontains $installDir) {
        Write-Host "$installDir is not on your PATH. Add it for future sessions:"
        Write-Host ""
        Write-Host "  [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path', 'User') + ';$installDir', 'User')"
        Write-Host ""
        Write-Host "Then open a new terminal and try:  hollow resolve example.com"
    } else {
        Write-Host "Try:  hollow resolve example.com"
    }
} finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
