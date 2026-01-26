# Sandbox plan execution (Pattern A)

## Execution flow
1) Dispatcher selects an `ExecutionPlan` and hands off to `SandboxExecutionRunner`.
2) `SandboxExecutionRunner` writes `/work/request.json` (includes `execution_plan` + context).
3) A localhost-only broker is started with a per-execution token.
4) The container entrypoint reads `/work/request.json`:
   - If `execution_plan` is present, it executes each ToolCall by calling the host broker.
   - If any tool is denied, it stops and writes `/work/result.json` with reasons/remediation.
   - On success, it writes `/work/result.json` with `tool_results` summary.
5) `SandboxExecutionRunner` reads `/work/result.json` and returns `ExecutionResult` to the dispatcher.

## Broker connectivity (Windows / Docker Desktop)
- Broker binds to `127.0.0.1` by default.
- For plan execution, the sandbox uses `host.docker.internal` and the broker binds to `0.0.0.0`
  with private/loopback-only client enforcement + per-execution token.
- Docker Desktop (Windows/macOS) provides `host.docker.internal`.
- Linux containers add `--add-host host.docker.internal:host-gateway` for local-only access.

## Security defaults
- Docker network is `none` by default; plan execution enables a local-only broker network.
- No secrets (secure store, USB keys, API keys) are mounted or passed into the container.
- `/input` is read-only; `/output` is writable and the only supported artifact output location.
