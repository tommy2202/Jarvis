## Jarvis (offline-first, secure, minimal)

This repo is a **minimal but functional** “Jarvis” assistant designed to run **offline-first** on Windows, with:

- **Config-driven Stage-A intent router** (keyword matching + confidence + basic args)
- **Stage-B local LLM fallback** (local HTTP to a model server, safe mock mode)
- **Single enforcement point** (dispatcher enforces permissions + admin gating)
- **Admin session** (passphrase hash stored in **encrypted secure store**; inactivity timeout)
- **USB-key encryption** (AES-GCM; default USB key path `E:\JARVIS_KEY.bin`)
- **Robust logging** (`logs/jarvis.log` + `logs/events.jsonl` with redaction)
- **CLI REPL** (`app.py`)
- **FastAPI remote control** (authenticated via API key stored **only** in encrypted secure store)
- **Module setup wizard** (detects modules and guides configuration)
- **Production-grade configuration system** (validated schemas, migrations, backups, hot reload)
- **Desktop UI (Tkinter)** (`python app.py --ui`) as a thin client over core runtime APIs
- **Telemetry + health monitoring** (local-only; `/health`, `/metrics`, UI “Health” tab, and authenticated web endpoints)

## Configuration system (production-grade)

### Directory layout

- `config/`: **non-sensitive** plaintext JSON configs (validated)
- `secure/`: encrypted secure store file(s) (requires USB key)
- `config/schema/`: (optional) JSON schema exports
- `config/backups/`: automatic backups + corrupt-file quarantine
  - `config/backups/last_known_good/`: last known good snapshot of `config/*.json`

### Single Config API (no ad-hoc JSON)

Jarvis uses a single validated config object:
- `jarvis/core/config/manager.py` → `ConfigManager`
- `jarvis/core/config/models.py` → pydantic schemas (**extra fields forbidden**)

On startup Jarvis:
- loads all `config/*.json`
- applies migrations based on `config/app.json` → `config_version`
- validates everything (clear errors)
- if a file is missing: writes safe defaults
- if a file is corrupt JSON: moves it to `config/backups/<name>.<ts>.corrupt.json` and restores last known good or defaults

### Versioning + migrations

`config/app.json` contains:
- `config_version`
- timestamps
- backup and hot-reload settings

Migrations live in `jarvis/core/config/migrations/` and run sequentially.
If migrations succeed, migrated configs are written back atomically with backups.

### Atomic writes + backups

All config writes are atomic (temp file + rename), and a timestamped backup is made before overwriting.
Backup retention is controlled by `config/app.json` → `backups.max_backups_per_file` (default 10).

### Sensitive vs non-sensitive

**Never stored in plaintext** (`config/*.json`):
- admin passphrase hash
- web API keys and metadata
- Porcupine access key
- lockout state for web security

These live only in the encrypted secure store (`secure/secure_store.enc`) via:
- `scripts/set_secret.py`

### Hot reload (optional, safe)

Hot reload is off by default (`config/app.json` → `hot_reload.enabled: false`).
When enabled:
- only non-sensitive configs are reloaded
- changes are debounced
- invalid changes are rejected and the previous config remains active

CLI commands:
- `/config status`
- `/config open`
- `/config validate`
- `/config reload`
- `/config diff`

## Windows setup

### 1) Create a venv + install dependencies

```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
python -m pip install -U pip
pip install -e ".[dev]"
```

### 2) Create the USB key (required for admin + secure store + web API key)

Insert your USB drive (default `E:\`), then:

```bash
python scripts\create_usb_key.py
```

This creates: `E:\JARVIS_KEY.bin`

### 3) Create/rotate the web API key (encrypted; USB required)

```bash
python scripts\rotate_api_key.py
```

It prints the new API key once; store it somewhere safe.

### 4) Enable the web server (optional)

Edit `config/web.json`:

- set `"enabled": true`
- set `"host": "0.0.0.0"` to allow LAN access (or keep `"127.0.0.1"` for local-only)
- set `"port": 8787` (or any free port)

Security note:
- If the **USB key is missing**, Jarvis will only bind the web server to **localhost** and **remote control endpoints will be disabled**.

## Running Jarvis

```bash
python app.py
```

## Desktop UI (Windows-first)

Launch the desktop UI (Tkinter):

```bash
python app.py --ui
```

UI config:
- `config/ui.json` controls refresh rate and log display limits.

Security model:
- The UI is a **thin client** only: it never runs intents directly.
- All actions go through Jarvis core APIs (same routing/dispatcher/admin checks).
- Admin-only UI controls are disabled unless admin is unlocked.

Keyboard shortcuts:
- **Enter**: send message (in the input box)

## Telemetry & health monitoring (local-only)

Jarvis collects **local-only** telemetry to help diagnose issues safely:

- **Health** (subsystems): config, secure store, runtime/state machine, dispatcher/router, LLM, jobs, web, voice/STT/TTS, UI
- **Metrics**: rolling counters/latencies/gauges (bounded in-memory)
- **Resources**: CPU/RAM/disk, best-effort GPU/VRAM on Windows (optional NVML)

Privacy guarantees:
- **No network export** (no external telemetry)
- **No secrets** (details are redacted)
- **No raw user messages** in telemetry

Config:
- `config/telemetry.json`

CLI:
- `/health` or `/health <subsystem>`
- `/metrics`
- `/metrics export <path>`
- `/telemetry status`
- `/telemetry reset` (admin only)

Web (authenticated):
- `GET /v1/health`
- `GET /v1/health/{subsystem}`
- `GET /v1/metrics`
- `GET /v1/telemetry/snapshot`

## Graceful shutdown + safe restart

Jarvis supports a **deterministic**, **logged** shutdown sequence that:
- stops accepting new requests (web/UI/CLI)
- drains/cancels jobs safely
- flushes/persists a runtime snapshot
- unloads heavy resources (LLM, audio/TTS threads)
- stops the web server in “draining mode”

Ops log:
- `logs/ops.jsonl`

Runtime state snapshot:
- `logs/runtime/state_snapshot.json`

CLI:
- `/shutdown` (may prompt for confirmation; controlled by `config/runtime.json`)
- `/restart` (admin-only by default; controlled by `config/runtime.json`)
- `/restart llm|web|voice|jobs` (best-effort subsystem restart)
- `/safe_mode restart` (restart with temporary safe-mode overrides)

Config:
- `config/runtime.json`

## Persistent runtime state (operational, no secrets)

Jarvis persists a **safe operational runtime state** across restarts (not chat memory) to support:
- resume diagnostics / post-mortem inspection
- crash recovery warnings (dirty shutdown detection)
- breaker state continuity

Storage (local):
- `runtime/state.json`
- `runtime/backups/`
- `runtime/last_known_good/`
- `runtime/crash_markers/dirty_shutdown.flag`
- `runtime/crash_markers/restart_marker.json`

Config:
- `config/runtime_state.json`

Privacy:
- no user message content
- no audio recordings
- no API keys / passphrases / secrets (only stored in encrypted secure store)

## Capabilities (unified policy enforcement)

Jarvis uses a **central capability model** as the source of truth for permissions. Capabilities are **independent of intents/modules** and are enforced **only in the dispatcher**.

Config:
- `config/capabilities.json` defines:
  - capability definitions
  - intent → required capabilities
  - source policies (web/voice stricter)
  - safe-mode denies

Hard safety rules (always enforced):
- `CAP_ADMIN_ACTION` always requires admin
- `CAP_IMAGE_GENERATION` and `CAP_CODE_GENERATION` always require admin
- `CAP_HEAVY_COMPUTE` requires admin unless explicitly whitelisted and not from web (fail-safe)
- during shutdown, only `CAP_READ_FILES` and `CAP_AUDIO_OUTPUT` are allowed

CLI:
- `/caps list`
- `/caps show <cap_id>`
- `/caps intent <intent_id>`
- `/caps eval <intent_id> --source=cli|web|voice|ui --admin=true|false --safe_mode=true|false --shutting_down=true|false`
- `/caps export <path>`

## Internal event bus (in-process)

Jarvis includes an **in-process internal event bus** used for monitoring and decoupled notifications (no IPC/network).

Config:
- `config/events.json`

Core events are written to:
- `logs/events/core_events.jsonl`

CLI:
- `/events status`
- `/events stats`
- `/events list-subscribers`
- `/events enable`
- `/events disable`
- `/events dump <path>` (admin-only)

CLI commands:
- `/admin unlock` (prompts for passphrase; no echo)
- `/admin lock`
- `/exit`

## Remote control (FastAPI)

When enabled, the server provides:
- `GET /health`
- `POST /v1/message` (requires `X-API-Key`)
- `POST /v1/admin/unlock` (requires `X-API-Key`; **localhost only by default**)
- `GET /` (tiny web UI, optional)

Example request:

```bash
curl -X POST "http://<jarvis-host>:8787/v1/message" ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: <YOUR_KEY>" ^
  -d "{\"message\":\"play Coldplay on Spotify\",\"client\":{\"name\":\"phone\"}}"
```

## Web security hardening (important)

Jarvis’s web interface is **safe by default**:
- Default bind is **localhost only** (`127.0.0.1`)
- Remote exposure must be explicitly enabled: `config/web.json` → `"allow_remote": true`
- If `"allow_remote": true` and the **USB key is missing**, Jarvis **refuses to start** the web server.

### API keys (encrypted, scoped, revocable)

API keys are stored **only** in the encrypted secure store and support:
- scopes: `read`, `message`, `admin`
- revocation + metadata
- per-key IP allowlists (optional)

Rotate/create a key (USB required):

```bash
python scripts/rotate_api_key.py
```

Or via CLI (admin required):
- `/web rotate-key`
- `/web list-keys`
- `/web revoke-key <id>`

### Rate limits + lockouts

Defaults (configurable in `config/web.json`):
- total requests: **60/min per IP**
- messages: **30/min per API key**
- admin actions: **5/min per API key**

Failed auth / rate limit hits accrue **strikes** and can trigger lockouts.
Lockout state is persisted in the encrypted secure store.

### Audit logging

Security events are written to:
- `logs/security.jsonl` (JSONL)

## Adding a module (setup wizard workflow)

1) Drop a new module file in `jarvis/modules/` with:
- `MODULE_META = {"id": "...", ...}`
- `handle(intent_id, args, context) -> dict`

2) Add it to `config/modules_registry.json` (or let the wizard detect it):

```json
{
  "modules": [
    {"module":"jarvis.modules.my_new_module","enabled": false}
  ]
}
```

3) Restart `python app.py`.
If the module is missing routing/permissions/confirmation config, Jarvis will prompt you through setup:
- admin-only?
- resource-intensive? (forces admin-only)
- needs network?
- keywords for routing
- confirmation template

Non-sensitive values go to `config/*.json`.
Secrets (if the module declares them) go into the **encrypted secure store** (USB required).

To run the wizard manually:

```bash
python scripts/jarvis_setup.py
```

## Local model server (optional)

Stage-B is designed to call a **local** model server via HTTP and validates strict JSON output.
If no local server is running, it falls back to **safe mock mode** (never executes unknown intents).

You can run a local server via Ollama or llama.cpp with an OpenAI-compatible endpoint.
Update `config/security.json` → `llm.base_url` and `llm.model`.

## Voice mode (Windows 10/11)

### Install voice dependencies

```bash
pip install -e ".[dev,voice]"
```

### PortAudio / sounddevice notes (Windows)

If `sounddevice` can’t open the microphone, install PortAudio support:
- Easiest: `pip install sounddevice` usually bundles what you need on Windows.
- If you see PortAudio DLL errors, install a PortAudio binary or use a Python distribution that includes it.

### Configure models (no auto-download)

Edit `config/models.json`:
- **Vosk**: set `"vosk_model_path"` to your local Vosk model folder.
  - Download a model from the official Vosk model list and unzip it.
- **faster-whisper**: set `"faster_whisper_model_path"` to a local faster-whisper model directory.
  - Use a pre-downloaded Whisper model converted for faster-whisper, stored locally.

Jarvis will **not** download models automatically; if paths are missing, STT will fail gracefully and return to sleep.

### Porcupine wake word (optional, offline)

Porcupine requires a Picovoice **AccessKey**, stored encrypted in the secure store:

```bash
python scripts/set_secret.py porcupine.access_key
```

If the key is missing, wake-word detection is disabled, but **push-to-talk still works**:
- Use `/listen` in the CLI to capture + transcribe + route + speak.

### Enable voice stack

Edit `config/voice.json`:
- set `"enabled": true`
- pick your mic with `/mics` then set `"mic_device_index"` (optional)

Run:

```bash
python app.py --mode hybrid
```

Useful commands:
- `/mics`
- `/listen` (push-to-talk)
- `/voice status`
- `/sleep`

## Job Manager

Jarvis includes a **process-based Job Manager** for long-running or blocking work:
- allowlisted job kinds only (no shell, no arbitrary execution)
- progress + events persisted under `logs/jobs/`
- cancellation + timeouts
- survives restarts (jobs can be inspected after restart)

CLI commands:
- `/jobs list [STATUS]`
- `/jobs show <job_id>`
- `/jobs cancel <job_id>`
- `/jobs tail <job_id> [n]`
- `/jobs run health_check`
- `/jobs run cleanup`

If web is enabled, authenticated job endpoints are available:
- `POST /v1/jobs`
- `GET /v1/jobs`
- `GET /v1/jobs/{job_id}`
- `POST /v1/jobs/{job_id}/cancel`

## Core State Machine (Runtime)

Jarvis now runs through a **single core runtime state machine** (`jarvis/core/runtime.py`) that:
- enforces explicit assistant states + valid transitions
- routes **CLI + web + (optional) voice** through the same pipeline
- coordinates **LLM lifecycle** (warm on wake / first input, unload after idle)
- persists state-machine events to `logs/state_machine/events.jsonl`

CLI commands:
- `/status` (shows current state + last trace_id)
- `/wake` (simulate wake)
- `/sleep` (unload and return to sleeping)
- `/shutdown`
- `/say <text>`

## LLM lifecycle control (Ollama recommended)

Jarvis supports two **local LLM roles**:
- **chat**: starts on wake/first message; unloads after idle
- **coder**: on-demand (CLI `/llm test coder ...`), then unloads immediately after use

Configuration: `config/llm.json`
- `mode: "external"` (default): Jarvis never starts/stops Ollama; it only calls `base_url`.
- `mode: "managed"`: Jarvis may attempt a best-effort `ollama serve` if the server is down.
  - By default Jarvis will **not** kill your Ollama server on idle (`managed_kill_server_on_idle: false`).

### Windows setup (Ollama)

1) Install Ollama for Windows.
2) Pull models (examples; use names that match your `config/llm.json`):

```bash
ollama pull qwen2.5:14b-instruct
ollama pull qwen3-coder:14b
```

3) Start Ollama (if using external mode):

```bash
ollama serve
```

### CLI commands

- `/llm status`
- `/llm unload chat|coder|all`
- `/llm test chat "hello"`
- `/llm test coder "write a python function that ..."`

### Web endpoint

If web is enabled, authenticated LLM status endpoint:
- `GET /v1/llm/status`

## Secure store operations (USB key)

Jarvis keeps secrets in an encrypted secure store:
- `secure/secure_store.enc` (AES‑GCM encrypted)
- `secure/store.meta.json` (plaintext non-sensitive metadata: store_id/key_id/version)
- `secure/backups/` (automatic backups and last-known-good)

### Status modes (operational clarity)

`/secure status` reports one of:
- `READY`: USB key present, store decryptable
- `KEY_MISSING`: USB key not found
- `STORE_MISSING`: store file missing (created on first secret write)
- `STORE_CORRUPT`: store exists but can’t be decrypted / JSON invalid
- `KEY_MISMATCH`: key present but doesn’t match store key_id
- `READ_ONLY`: store readable but writes blocked

### CLI helpers

- `/secure status`
- `/secure keys`
- `/secure get <key> [--show]` (admin-only; redacts unless `--show`)
- `/secure set <key>` (admin-only, hidden input)
- `/secure delete <key>` (admin-only)
- `/secure backup` (admin-only)
- `/secure restore list` / `/secure restore <backup_file>` (admin-only)
- `/secure rotate` (prints rotation instructions)

Scripts:
- `python scripts/create_usb_key.py` (creates key, prints key_id)
- `python scripts/check_usb_key.py` (prints key_id)
- `python scripts/rotate_usb_key.py` (safe rotation with `.new` files; `--apply` to swap)
- `python scripts/restore_secure_store.py --list` / `python scripts/restore_secure_store.py <backup>`

### Web endpoint

Authenticated public status only:
- `GET /v1/secure/status`

## Error handling & recovery policy

Jarvis uses a unified, production-grade error policy to prevent crashes and fail safe:

- **Typed taxonomy**: `jarvis/core/errors.py` defines stable error codes, safe user messages, severity, and redacted context.
- **Error reporting**: `logs/errors.jsonl` stores structured error reports (secrets redacted; tracebacks off by default).
- **Deterministic recovery**: `jarvis/core/recovery.py` decides actions (retry/fallback/sleep/abort) based on error type.
- **Circuit breakers**: `jarvis/core/circuit_breaker.py` prevents thrashing when subsystems repeatedly fail (LLM/STT/TTS/etc.).

Config: `config/recovery.json`:
- debug flags (`include_tracebacks` default false)
- retry/backoff for timeouts
- breaker thresholds/window/cooldowns

CLI diagnostics:
- `/errors last [n]`
- `/errors show <trace_id>`
- `/errors export <path>`
- `/health` (subsystem breaker states + last-known status)
- `/debug enable|disable` (admin-only; toggles traceback logging temporarily)

## Testing

Run tests:

```bash
pytest
pytest -q
pytest --maxfail=1
```

Coverage:

```bash
coverage run -m pytest
coverage report -m
```
