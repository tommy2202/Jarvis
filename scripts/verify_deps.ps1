$ErrorActionPreference = "Stop"

$py = "py -3.11"
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    $py = "python"
}

if (-not (Test-Path -Path "requirements.txt")) {
    throw "requirements.txt missing. Run scripts/lock_deps.ps1."
}

$code = @"
import sys
from pathlib import Path

path = Path("requirements.txt")
text = path.read_text(encoding="utf-8").splitlines()

def is_req_line(line: str) -> bool:
    if not line:
        return False
    if line.startswith("#"):
        return False
    if line.startswith("    --hash"):
        return False
    if line.startswith("-r ") or line.startswith("--"):
        return False
    return True

errors = []
idx = 0
while idx < len(text):
    line = text[idx].strip()
    if is_req_line(line):
        if "==" not in line:
            errors.append(f"Unpinned requirement: {line}")
        # Require at least one hash line before next requirement
        has_hash = False
        j = idx + 1
        while j < len(text):
            nxt = text[j].strip()
            if is_req_line(nxt):
                break
            if "--hash=" in nxt:
                has_hash = True
            j += 1
        if not has_hash:
            errors.append(f"Missing hashes for: {line}")
        idx = j
        continue
    idx += 1

if errors:
    for e in errors:
        print(e)
    sys.exit(2)
print("Dependency lock verified.")
"@

& $py -c $code
