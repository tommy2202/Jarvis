$ErrorActionPreference = "Stop"

$py = "py -3.11"
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    $py = "python"
}

Write-Host "Locking dependencies via pip-tools..."
& $py -m piptools compile --generate-hashes --allow-unsafe --resolver=backtracking --output-file requirements.txt requirements.in
if ($LASTEXITCODE -ne 0) {
    throw "pip-compile failed. Ensure pip-tools is installed."
}

Write-Host "Updated requirements.txt"
