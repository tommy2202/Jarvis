$ErrorActionPreference = "Stop"

$py = "py -3.11"
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    $py = "python"
}

Write-Host "Running unit tests..."
& $py -m pytest -q
if ($LASTEXITCODE -ne 0) {
    throw "pytest failed."
}

Write-Host "Running core smoke check..."
& $py "scripts/verify_core.py"
if ($LASTEXITCODE -ne 0) {
    throw "verify_core failed."
}

Write-Host "Dev check completed."
