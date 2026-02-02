$ErrorActionPreference = "Stop"

param(
    [switch]$UseVenv,
    [switch]$CreateVenv
)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$venvPath = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

function Resolve-SystemPython {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @("py", "-3.11")
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @("python")
    }
    throw "Python not found. Install Python or create a venv."
}

function Invoke-Python {
    param([string[]]$Py, [string[]]$Args)
    if ($Py.Length -ge 2) {
        & $Py[0] $Py[1] @Args
    } else {
        & $Py[0] @Args
    }
    if ($LASTEXITCODE -ne 0) {
        throw ("Python command failed: " + ($Args -join " "))
    }
}

Set-Location $repoRoot

$py = @()
if ($UseVenv -or $CreateVenv) {
    if (-not (Test-Path $venvPython)) {
        if (-not $CreateVenv) {
            throw "Venv not found. Re-run with -CreateVenv or create .venv first."
        }
        $sysPy = Resolve-SystemPython
        Write-Host "Creating venv at $venvPath..."
        Invoke-Python -Py $sysPy -Args @("-m", "venv", $venvPath)
    }
    $py = @($venvPython)
} elseif (Test-Path $venvPython) {
    $py = @($venvPython)
} else {
    $py = Resolve-SystemPython
}

Write-Host "Running bytecode compilation..."
Invoke-Python -Py $py -Args @("-m", "compileall", "jarvis")

Write-Host "Running unit tests..."
Invoke-Python -Py $py -Args @("-m", "pytest", "-q")

Write-Host "Dev check completed."
