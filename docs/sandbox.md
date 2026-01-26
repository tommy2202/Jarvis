# Sandbox execution (Docker)

This document describes the Docker-based sandbox used for **Pattern A** and how it will evolve toward **Pattern B**.

## Threat model (Pattern A)

Goals:
- Isolate risky execution (subprocess, network, heavy compute, image/code generation) from the host.
- Prevent access to secrets (USB key, secure store, API keys).
- Restrict network access by default.
- Keep artifacts explicit and auditable.

Assumptions:
- Docker provides a stronger boundary than running in-process.
- The sandbox is a **best-effort isolation layer**, not a perfect security boundary.
- If Docker is unavailable and `execution.sandbox.require_available=true`, risky execution is denied.

## Security defaults

- **Network disabled** (`--network none`).
- **Input** mounted **read-only** at `/input`.
- **Output** mounted **read-write** at `/output`.
- **Work** directory is **ephemeral** at `/work`.
- **No secrets are mounted** (secure store, USB keys, tokens).
- Broker IPC (when enabled) is **localhost-only** with a short-lived token.

## Limitations

- A container is still a **process on the host**; it is not a perfect sandbox.
- If Docker is not used (fallback to local runner), there is **no sandbox boundary**.
- Resource limits (CPU/memory/pids/timeout) are best-effort and depend on host configuration.

## Pattern B migration (conceptual)

Pattern B introduces **plan-based execution** with **brokered tools**:

1) Dispatcher builds an **ExecutionPlan**:
   - a list of `ToolCall` steps (tool_name, tool_args, requested_caps, expected_artifacts).
2) The sandboxed runtime **does not call tools directly**.
3) Instead, the sandbox calls the **Broker Server**:
   - IPC is local-only (127.0.0.1)
   - A **short-lived token** is required per execution
4) The Broker Server:
   - Rebuilds a **RequestContext**
   - Re-runs **CapabilityEngine** + **PolicyEngine**
   - Audits the call and redacts details
   - Denies unknown tools by default

This keeps the **dispatcher as the single enforcement point** while allowing future
safe tool execution paths without exposing secrets to the container.

## Files

- `docker/sandbox/Dockerfile.sandbox` – Docker image build
- `jarvis/core/execution/sandbox_runner.py` – sandbox runner (Pattern A)
- `jarvis/core/broker/server.py` – broker IPC server (scaffolding for Pattern B)
