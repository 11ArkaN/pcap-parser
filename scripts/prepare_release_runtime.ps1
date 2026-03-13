param(
  [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$pythonVersion = "3.12.10"
$pythonZipUrl = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion-embed-amd64.zip"
$pipBootstrapUrl = "https://bootstrap.pypa.io/get-pip.py"
$procmonZipUrl = "https://download.sysinternals.com/files/ProcessMonitor.zip"

$runtimeDir = Join-Path $RepoRoot "python"
$pythonExePath = Join-Path $runtimeDir "python.exe"
$requirementsPath = Join-Path $RepoRoot "sidecar\requirements.txt"
$procmonDir = Join-Path $RepoRoot "vendor\procmon"
$logPath = Join-Path $RepoRoot "tmp\prepare_release_runtime.log"

New-Item -ItemType Directory -Path (Split-Path -Parent $logPath) -Force | Out-Null
Set-Content -Path $logPath -Value @("=== prepare_release_runtime.ps1 ===", "ts: $(Get-Date -Format o)", "repoRoot: $RepoRoot", "") -Encoding utf8

function Write-Step {
  param([string]$Message)
  Write-Host "[release-runtime] $Message"
  Add-Content -Path $logPath -Value "[release-runtime] $Message"
}

function Invoke-Checked {
  param(
    [string]$FilePath,
    [string[]]$Arguments,
    [string]$StepName
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$StepName nie powiodl sie. Exit code: $LASTEXITCODE"
  }
}

function Download-File {
  param(
    [string]$Url,
    [string]$Destination
  )

  Write-Step "Pobieranie: $Url"
  Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -TimeoutSec 180
}

function Ensure-EmbeddedPython {
  if (Test-Path $pythonExePath) {
    Write-Step "Embedded Python juz istnieje."
    return
  }

  Write-Step "Przygotowanie embedded Python $pythonVersion..."
  New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null

  $tempZip = Join-Path $env:TEMP ("pcap-analyzer-python-{0}.zip" -f ([Guid]::NewGuid().ToString("N")))
  $tempExtractDir = Join-Path $env:TEMP ("pcap-analyzer-python-{0}" -f ([Guid]::NewGuid().ToString("N")))

  try {
    Download-File -Url $pythonZipUrl -Destination $tempZip
    Expand-Archive -Path $tempZip -DestinationPath $tempExtractDir -Force
    Copy-Item -Path (Join-Path $tempExtractDir "*") -Destination $runtimeDir -Recurse -Force
  }
  finally {
    if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempExtractDir) { Remove-Item $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
  }

  if (-not (Test-Path $pythonExePath)) {
    throw "Nie znaleziono python.exe po rozpakowaniu embedded runtime."
  }
}

function Enable-EmbeddedSitePackages {
  $pthFile = Get-ChildItem -Path $runtimeDir -Filter "python*._pth" -File | Select-Object -First 1
  if (-not $pthFile) {
    throw "Nie znaleziono pliku python*._pth w $runtimeDir"
  }

  $lines = Get-Content $pthFile.FullName
  $normalized = @()
  foreach ($line in $lines) {
    if ($line.Trim() -eq "#import site" -or $line.Trim() -eq "import site") {
      continue
    }
    $normalized += $line
  }

  if (-not ($normalized -contains "Lib")) { $normalized += "Lib" }
  if (-not ($normalized -contains "Lib\site-packages")) { $normalized += "Lib\site-packages" }
  $normalized += "import site"

  Set-Content -Path $pthFile.FullName -Value $normalized -Encoding ascii
  New-Item -ItemType Directory -Path (Join-Path $runtimeDir "Lib\site-packages") -Force | Out-Null
}

function Test-PythonModule {
  param([string]$ModuleName)

  if (-not (Test-Path $pythonExePath)) {
    return $false
  }

  $previousPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    & $pythonExePath -c "import $ModuleName" 1>$null 2>$null
    return $LASTEXITCODE -eq 0
  }
  finally {
    $ErrorActionPreference = $previousPreference
  }
}

function Ensure-Pip {
  if (Test-PythonModule -ModuleName "pip") {
    Write-Step "pip juz zainstalowany."
    return
  }

  Write-Step "Instalacja pip..."
  $tempGetPip = Join-Path $env:TEMP ("pcap-analyzer-get-pip-{0}.py" -f ([Guid]::NewGuid().ToString("N")))

  try {
    Download-File -Url $pipBootstrapUrl -Destination $tempGetPip
    Invoke-Checked -FilePath $pythonExePath -Arguments @($tempGetPip, "--disable-pip-version-check") -StepName "Instalacja pip"
  }
  finally {
    if (Test-Path $tempGetPip) { Remove-Item $tempGetPip -Force -ErrorAction SilentlyContinue }
  }
}

function Install-SidecarRequirements {
  if (Test-PythonModule -ModuleName "procmon_parser") {
    Write-Step "procmon_parser juz zainstalowany."
    return
  }

  if (-not (Test-Path $requirementsPath)) {
    throw "Nie znaleziono pliku requirements: $requirementsPath"
  }

  Write-Step "Instalacja zaleznosci sidecara do bundla..."
  Invoke-Checked -FilePath $pythonExePath -Arguments @("-m", "pip", "install", "-r", $requirementsPath, "--disable-pip-version-check", "--no-warn-script-location") -StepName "Instalacja sidecar requirements"
}

function Test-ProcmonExecutable {
  param([string]$ExecutablePath)

  if (-not (Test-Path $ExecutablePath)) {
    return $false
  }

  $item = Get-Item -Path $ExecutablePath -ErrorAction SilentlyContinue
  if (-not $item -or $item.Length -lt 500000) {
    return $false
  }

  try {
    $stream = [System.IO.File]::OpenRead($ExecutablePath)
    $header = New-Object byte[] 2
    $readBytes = $stream.Read($header, 0, 2)
    $stream.Close()
    return $readBytes -eq 2 -and $header[0] -eq 0x4D -and $header[1] -eq 0x5A
  }
  catch {
    return $false
  }
}

function Test-ProcmonBundleComplete {
  param([string]$ProcmonDir)

  $procmon64 = Join-Path $ProcmonDir "Procmon64.exe"
  $procmon32 = Join-Path $ProcmonDir "Procmon.exe"
  $eulaPath = Join-Path $ProcmonDir "Eula.txt"

  $has64 = Test-ProcmonExecutable -ExecutablePath $procmon64
  $has32 = Test-ProcmonExecutable -ExecutablePath $procmon32
  $hasEula = Test-Path $eulaPath

  if (-not $has64) {
    Write-Step "Brak poprawnego Procmon64.exe w bundlu, wymagana naprawa."
  }

  if (-not $has32) {
    Write-Step "Brak poprawnego Procmon.exe w bundlu, wymagana naprawa."
  }

  if (-not $hasEula) {
    Write-Step "Brak Eula.txt w bundlu Procmon, wymagana naprawa."
  }

  return $has64 -and $has32 -and $hasEula
}

function Ensure-ProcmonBinary {
  New-Item -ItemType Directory -Path $procmonDir -Force | Out-Null
  $procmon64 = Join-Path $procmonDir "Procmon64.exe"
  $procmon32 = Join-Path $procmonDir "Procmon.exe"

  if (Test-ProcmonBundleComplete -ProcmonDir $procmonDir) {
    Write-Step "Procmon bundle juz kompletny."
    return
  }

  Write-Step "Pobieranie Procmon do bundla..."
  $tempZip = Join-Path $env:TEMP ("pcap-analyzer-procmon-{0}.zip" -f ([Guid]::NewGuid().ToString("N")))
  $tempExtractDir = Join-Path $env:TEMP ("pcap-analyzer-procmon-{0}" -f ([Guid]::NewGuid().ToString("N")))

  try {
    if (Test-Path $procmon64) { Remove-Item $procmon64 -Force -ErrorAction SilentlyContinue }
    if (Test-Path $procmon32) { Remove-Item $procmon32 -Force -ErrorAction SilentlyContinue }
    if (Test-Path (Join-Path $procmonDir "Eula.txt")) { Remove-Item (Join-Path $procmonDir "Eula.txt") -Force -ErrorAction SilentlyContinue }
    Download-File -Url $procmonZipUrl -Destination $tempZip
    Expand-Archive -Path $tempZip -DestinationPath $tempExtractDir -Force
    Copy-Item -Path (Join-Path $tempExtractDir "Procmon64.exe") -Destination $procmon64 -Force -ErrorAction SilentlyContinue
    Copy-Item -Path (Join-Path $tempExtractDir "Procmon.exe") -Destination $procmon32 -Force -ErrorAction SilentlyContinue
    Copy-Item -Path (Join-Path $tempExtractDir "Eula.txt") -Destination (Join-Path $procmonDir "Eula.txt") -Force -ErrorAction SilentlyContinue
  }
  finally {
    if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempExtractDir) { Remove-Item $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
  }

  if (-not (Test-ProcmonBundleComplete -ProcmonDir $procmonDir)) {
    throw "Nie udalo sie przygotowac kompletnego bundla Procmon."
  }
}

function Verify-Runtime {
  Write-Step "Weryfikacja pip..."
  Invoke-Checked -FilePath $pythonExePath -Arguments @("-m", "pip", "--version") -StepName "Weryfikacja pip"
  Write-Step "Weryfikacja procmon_parser..."
  Invoke-Checked -FilePath $pythonExePath -Arguments @("-c", "import procmon_parser; print('procmon_parser: OK')") -StepName "Weryfikacja procmon_parser"
}

try {
  Write-Step "Start przygotowania runtime do releasu."
  Ensure-ProcmonBinary
  Ensure-EmbeddedPython
  Enable-EmbeddedSitePackages
  Ensure-Pip
  Install-SidecarRequirements
  Verify-Runtime
  Write-Step "Runtime do releasu gotowy."
  exit 0
}
catch {
  $message = $_.Exception.Message
  Add-Content -Path $logPath -Value ""
  Add-Content -Path $logPath -Value "[release-runtime] ERROR: $message"
  Add-Content -Path $logPath -Value $_.ScriptStackTrace
  Write-Error $message
  exit 1
}
