param(
  [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$ReleaseRoot = "release"
)

$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host "[verify-release] $Message"
}

function Assert-PathExists {
  param(
    [string]$TargetPath,
    [string]$Description
  )

  if (-not (Test-Path $TargetPath)) {
    throw "Brak ${Description}: $TargetPath"
  }
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

$resolvedReleaseRoot =
  if ([System.IO.Path]::IsPathRooted($ReleaseRoot)) {
    $ReleaseRoot
  } else {
    Join-Path $RepoRoot $ReleaseRoot
  }

$resourcesDir = Join-Path $resolvedReleaseRoot "win-unpacked\resources"
$builderDebugPath = Join-Path $resolvedReleaseRoot "builder-debug.yml"
$pythonExePath = Join-Path $resourcesDir "python\python.exe"
$pipExePath = Join-Path $resourcesDir "python\Scripts\pip.exe"
$sidecarScriptPath = Join-Path $resourcesDir "sidecar\job_runner.py"
$installerScriptPath = Join-Path $resourcesDir "sidecar\install_runtime.ps1"
$requirementsPath = Join-Path $resourcesDir "sidecar\requirements.txt"
$procmon64Path = Join-Path $resourcesDir "procmon\Procmon64.exe"
$procmon32Path = Join-Path $resourcesDir "procmon\Procmon.exe"
$procmonEulaPath = Join-Path $resourcesDir "procmon\Eula.txt"

Write-Step "Weryfikacja zasobow release w $resolvedReleaseRoot"
Assert-PathExists -TargetPath $resourcesDir -Description "katalogu resources"
Assert-PathExists -TargetPath $builderDebugPath -Description "builder-debug.yml"
Assert-PathExists -TargetPath $sidecarScriptPath -Description "sidecar/job_runner.py"
Assert-PathExists -TargetPath $installerScriptPath -Description "sidecar/install_runtime.ps1"
Assert-PathExists -TargetPath $requirementsPath -Description "sidecar/requirements.txt"
Assert-PathExists -TargetPath $pythonExePath -Description "python/python.exe"
Assert-PathExists -TargetPath $pipExePath -Description "python/Scripts/pip.exe"
Assert-PathExists -TargetPath $procmonEulaPath -Description "procmon/Eula.txt"

if (-not (Test-ProcmonExecutable -ExecutablePath $procmon64Path)) {
  throw "Brak poprawnego Procmon64.exe w release: $procmon64Path"
}

if (-not (Test-ProcmonExecutable -ExecutablePath $procmon32Path)) {
  throw "Brak poprawnego Procmon.exe w release: $procmon32Path"
}

Write-Step "Weryfikacja importow Pythona sidecara"
Invoke-Checked -FilePath $pythonExePath -Arguments @("-c", "import pip, procmon_parser; print('release-runtime: OK')") -StepName "Import pip/procmon_parser"

$builderDebug = Get-Content $builderDebugPath -Raw
if ($builderDebug -notmatch [regex]::Escape("installer.internal.nsh")) {
  throw "builder-debug.yml nie zawiera build/installer.internal.nsh, instalator nie uruchomi bootstrapu runtime."
}

Write-Step "Release bundle wyglada poprawnie."
