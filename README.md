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
