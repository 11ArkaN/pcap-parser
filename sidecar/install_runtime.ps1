param(
  [Parameter(Mandatory = $true)]
  [string]$InstallDir
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$pythonVersion = "3.12.10"
$pythonZipUrl = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion-embed-amd64.zip"
$pipBootstrapUrl = "https://bootstrap.pypa.io/get-pip.py"
$procmonZipUrl = "https://download.sysinternals.com/files/ProcessMonitor.zip"
$logPath = Join-Path $InstallDir "install_runtime.log"
Set-Content -Path $logPath -Value @("=== install_runtime.ps1 ===", "ts: $(Get-Date -Format o)", "installDir: $InstallDir", "") -Encoding utf8

function Write-Step {
  param([string]$Message)
  Write-Host "[runtime] $Message"
  Add-Content -Path $logPath -Value "[runtime] $Message"
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
  Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -TimeoutSec 120
}

function Ensure-EmbeddedPython {
  param(
    [string]$RuntimeDir,
    [string]$PythonExePath
  )

  if (Test-Path $PythonExePath) {
    Write-Step "Python runtime juz istnieje."
    return
  }

  Write-Step "Instalacja embedded Python $pythonVersion..."
  New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null

  $tempZip = Join-Path $env:TEMP ("pcap-analyzer-python-{0}.zip" -f ([Guid]::NewGuid().ToString("N")))
  $tempExtractDir = Join-Path $env:TEMP ("pcap-analyzer-python-{0}" -f ([Guid]::NewGuid().ToString("N")))

  try {
    Download-File -Url $pythonZipUrl -Destination $tempZip
    Expand-Archive -Path $tempZip -DestinationPath $tempExtractDir -Force
    Copy-Item -Path (Join-Path $tempExtractDir "*") -Destination $RuntimeDir -Recurse -Force
  }
  finally {
    if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempExtractDir) { Remove-Item $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
  }

  if (-not (Test-Path $PythonExePath)) {
    throw "Nie znaleziono python.exe po rozpakowaniu embedded runtime."
  }
}

function Test-ProcmonExecutable {
  param([string]$ExecutablePath)

  if (-not (Test-Path $ExecutablePath)) {
    return $false
  }

  $item = Get-Item -Path $ExecutablePath -ErrorAction SilentlyContinue
  if (-not $item -or $item.Length -lt 500000) {
    Write-Step "Procmon candidate odrzucony (zly rozmiar): $ExecutablePath"
    return $false
  }

  try {
    $stream = [System.IO.File]::OpenRead($ExecutablePath)
    $header = New-Object byte[] 2
    $readBytes = $stream.Read($header, 0, 2)
    $stream.Close()
    if ($readBytes -ne 2 -or $header[0] -ne 0x4D -or $header[1] -ne 0x5A) {
      Write-Step "Procmon candidate odrzucony (brak naglowka PE): $ExecutablePath"
      return $false
    }
  } catch {
    Write-Step "Procmon candidate odrzucony (blad odczytu): $ExecutablePath"
    return $false
  }

  return $true
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
    Write-Step "Brak poprawnego Procmon64.exe, wymagana naprawa."
  }

  if (-not $has32) {
    Write-Step "Brak poprawnego Procmon.exe, wymagana naprawa."
  }

  if (-not $hasEula) {
    Write-Step "Brak Eula.txt dla Procmon, wymagana naprawa."
  }

  return $has64 -and $has32 -and $hasEula
}

function Ensure-ProcmonBinary {
  param([string]$ProcmonDir)

  New-Item -ItemType Directory -Path $ProcmonDir -Force | Out-Null
  $procmon64 = Join-Path $ProcmonDir "Procmon64.exe"
  $procmon32 = Join-Path $ProcmonDir "Procmon.exe"

  if (Test-ProcmonBundleComplete -ProcmonDir $ProcmonDir) {
    Write-Step "Procmon bundle juz kompletny."
    return
  }

  Write-Step "Instalacja/naprawa Procmon (Sysinternals)..."
  $tempZip = Join-Path $env:TEMP ("pcap-analyzer-procmon-{0}.zip" -f ([Guid]::NewGuid().ToString("N")))
  $tempExtractDir = Join-Path $env:TEMP ("pcap-analyzer-procmon-{0}" -f ([Guid]::NewGuid().ToString("N")))

  try {
    if (Test-Path $procmon64) { Remove-Item $procmon64 -Force -ErrorAction SilentlyContinue }
    if (Test-Path $procmon32) { Remove-Item $procmon32 -Force -ErrorAction SilentlyContinue }
    Download-File -Url $procmonZipUrl -Destination $tempZip
    Expand-Archive -Path $tempZip -DestinationPath $tempExtractDir -Force
    Copy-Item -Path (Join-Path $tempExtractDir "Procmon64.exe") -Destination $procmon64 -Force -ErrorAction SilentlyContinue
    Copy-Item -Path (Join-Path $tempExtractDir "Procmon.exe") -Destination $procmon32 -Force -ErrorAction SilentlyContinue
    Copy-Item -Path (Join-Path $tempExtractDir "Eula.txt") -Destination (Join-Path $ProcmonDir "Eula.txt") -Force -ErrorAction SilentlyContinue
  }
  finally {
    if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempExtractDir) { Remove-Item $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
  }

  if (-not (Test-ProcmonBundleComplete -ProcmonDir $ProcmonDir)) {
    throw "Nie udalo sie zainstalowac kompletnego bundla Procmon."
  }
}

function Enable-EmbeddedSitePackages {
  param([string]$RuntimeDir)

  $pthFile = Get-ChildItem -Path $RuntimeDir -Filter "python*._pth" -File | Select-Object -First 1
  if (-not $pthFile) {
    Write-Step "Brak pliku ._pth, pomijam konfiguracje site-packages."
    return
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
  New-Item -ItemType Directory -Path (Join-Path $RuntimeDir "Lib\site-packages") -Force | Out-Null
}

function Ensure-Pip {
  param([string]$PythonExePath)

  $runtimeDir = Split-Path -Parent $PythonExePath
  $pipInitPath = Join-Path $runtimeDir "Lib\site-packages\pip\__init__.py"
  if (Test-Path $pipInitPath) {
    Write-Step "pip juz zainstalowany."
    return
  }

  Write-Step "Instalacja pip..."
  $tempGetPip = Join-Path $env:TEMP ("pcap-analyzer-get-pip-{0}.py" -f ([Guid]::NewGuid().ToString("N")))

  try {
    Download-File -Url $pipBootstrapUrl -Destination $tempGetPip
    Invoke-Checked -FilePath $PythonExePath -Arguments @($tempGetPip, "--disable-pip-version-check") -StepName "Instalacja pip"
  }
  finally {
    if (Test-Path $tempGetPip) { Remove-Item $tempGetPip -Force -ErrorAction SilentlyContinue }
  }
}

function Test-PythonModule {
  param(
    [string]$PythonExePath,
    [string]$ModuleName
  )

  if (-not (Test-Path $PythonExePath)) {
    return $false
  }

  $previousPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    & $PythonExePath -c "import $ModuleName" 1>$null 2>$null
    return $LASTEXITCODE -eq 0
  }
  finally {
    $ErrorActionPreference = $previousPreference
  }
}

function Install-SidecarRequirements {
  param(
    [string]$PythonExePath,
    [string]$RequirementsPath
  )

  if (-not (Test-Path $RequirementsPath)) {
    throw "Nie znaleziono pliku requirements: $RequirementsPath"
  }

  if (Test-PythonModule -PythonExePath $PythonExePath -ModuleName "procmon_parser") {
    Write-Step "procmon_parser juz dostepny, pomijam instalacje requirements."
    return
  }

  Write-Step "Instalacja zaleznosci sidecara..."
  Invoke-Checked -FilePath $PythonExePath -Arguments @("-m", "pip", "install", "-r", $RequirementsPath, "--disable-pip-version-check", "--no-warn-script-location") -StepName "Instalacja sidecar requirements"
}

function Verify-ProcmonParser {
  param([string]$PythonExePath)

  Write-Step "Weryfikacja procmon_parser..."
  Invoke-Checked -FilePath $PythonExePath -Arguments @("-c", "import procmon_parser; print('procmon_parser: OK')") -StepName "Weryfikacja procmon_parser"
}

try {
  $resourcesDir = Join-Path $InstallDir "resources"
  $runtimeDir = Join-Path $resourcesDir "python"
  $pythonExePath = Join-Path $runtimeDir "python.exe"
  $requirementsPath = Join-Path $resourcesDir "sidecar\requirements.txt"
  $procmonDir = Join-Path $resourcesDir "procmon"

  Write-Step "Start bootstrap runtime."
  Ensure-ProcmonBinary -ProcmonDir $procmonDir
  Ensure-EmbeddedPython -RuntimeDir $runtimeDir -PythonExePath $pythonExePath
  Enable-EmbeddedSitePackages -RuntimeDir $runtimeDir
  Ensure-Pip -PythonExePath $pythonExePath
  Install-SidecarRequirements -PythonExePath $pythonExePath -RequirementsPath $requirementsPath
  Verify-ProcmonParser -PythonExePath $pythonExePath
  Write-Step "Bootstrap runtime zakonczony powodzeniem."
  exit 0
} catch {
  $message = $_.Exception.Message
  Add-Content -Path $logPath -Value ""
  Add-Content -Path $logPath -Value "[runtime] ERROR: $message"
  Add-Content -Path $logPath -Value $_.ScriptStackTrace
  Write-Error $message
  exit 1
}
