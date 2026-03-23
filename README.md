# Interactive Dynamic Analysis

Python runtime for interactive userspace binary analysis, using instrumented `qemu-user` as the first backend.

This project is analysis-first: it focuses on controllable execution plus structured state/event inspection for human and LLM workflows.

## Repository Contents

- runtime implementation in `src/interactive_analysis/`
- tests in `tests/`
- runnable examples in `examples/`
- architecture and scope notes in `design.md`
- live backend contract in `docs/live_backend_contract.md`
- project planning in `docs/project_plan.md`
- LLM operation guidance in `docs/LLM_PLAYBOOK.md`

## Quick Setup

Requirements:

- Python 3.11+
- (for demos) `gcc` and `qemu-x86_64`

Create a local environment and install dev dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
.venv/bin/python -m pip install -e '.[dev]'
```

## Tests

Run the default test suite:

```bash
PYTHONPATH=src .venv/bin/pytest -q
```

### Live QEMU Integration Tests (opt-in)

Live tests are marked `live_qemu` and require a real backend/instrumentation environment.

Set:

- `RUN_LIVE_QEMU=1`
- `IA_LIVE_EVENT_SOCKET`
- `IA_LIVE_RPC_SOCKET`
- `IA_LIVE_TARGET`

Optional:

- `IA_LIVE_QMP_SOCKET`
- `IA_LIVE_ARGS`
- `IA_LIVE_CWD`
- `IA_LIVE_LAUNCH=1`
- `IA_LIVE_QEMU_USER_PATH`
- `IA_LIVE_QEMU_ARGS`

Then run:

```bash
PYTHONPATH=src .venv/bin/pytest -q -m live_qemu
```

`IA_LIVE_LAUNCH=1` tells the backend to launch `qemu-user` using the runtime launch contract. If unset, tests assume endpoints already exist.

## Demos

### End-to-end local demo

```bash
PYTHONPATH=src .venv/bin/python examples/demo_live_session.py
```

This demo will:

1. compile `examples/sample_target.c`
2. start `examples/instrumentation_sidecar.py`
3. launch the target through the runtime with `qemu-user`
4. run a short analysis session

### Real QEMU RPC slice (M1)

```bash
PYTHONPATH=src .venv/bin/python examples/demo_qemu_rpc_m1.py
```

This path expects a locally built QEMU binary at `/home/heng/git/qemu/build-ia/qemu-x86_64` and exercises:

1. `query_status`
2. `get_registers`
3. `advance_basic_blocks(1)`
4. `disassemble(...)` from live runtime `rip`
5. `run_until_address(...)` using a future instruction address
6. `read_memory`

## MCP Server (stdio)

The repo includes a minimal MCP server for external coding platforms.

Start it with:

```bash
PYTHONPATH=src .venv/bin/python -m dynamiq.mcp_server
```

Backward-compatible module path is still supported:

```bash
PYTHONPATH=src .venv/bin/python -m interactive_analysis.mcp_server
```

### Supported MCP methods

- `initialize`
- `tools/list`
- `tools/call`

### Exposed tools

- `start`, `close`, `caps`, `state`
- `run`, `pause`
- `send_bytes`, `send_line`, `send_file`, `stdout`, `stderr`
- `regs`, `disasm`, `mem`, `maps`, `syms`
- `step`, `bb`
- `bp_add`, `bp_del`, `bp_list`, `bp_clear`

### MCP quickstart for interactive stdin/stdout

Use this order for interactive programs:

1. `start`
2. `run`
3. one or more `send_bytes` / `send_line` / `send_file`
4. poll `stdout` and `stderr`

Example `tools/call` arguments:

- `start`
```json
{
  "target": "/home/heng/work2/KPRCA_00021",
  "cwd": "/home/heng/work2"
}
```

- `run`
```json
{
  "timeout": 5.0
}
```

- `send_bytes` (required `data`)
```json
{
  "data": "1\\n"
}
```

- `send_bytes` (raw bytes via hex)
```json
{
  "data_hex": "040000000680ffffffffffff"
}
```

- `send_line` (optional `line`, appends `\n`)
```json
{
  "line": "1"
}
```

- `send_file` (required `path`, streams raw file bytes)
```json
{
  "path": "/tmp/pov_input.txt",
  "append_newline": true
}
```

- `stdout` / `stderr`
```json
{
  "max_chars": 4096,
  "wait_ms": 150
}
```

`stdout` and `stderr` return `data`, `cursor`, and `eof`. The server tracks cursors internally, so repeated calls return only new output by default.

### MCP troubleshooting

- `send_bytes` appears stuck:
  Call includes neither `data` nor `data_hex`. Send `{"data":"...\\n"}` for text or `{"data_hex":"..."}` for raw bytes.
- `run` returns timeout:
  This is often expected for interactive flows (waiting for input or breakpoint condition). Treat as non-fatal and immediately check `stdout`, `stderr`, and `state`.
- Session is `idle` and target is not running:
  Use `start` (defaults to launch mode), then `run`.
- Large multiline payloads fail in tool UI:
  Use `send_file` (preferred) or split into multiple `send_bytes` calls.

## Reference Docs

- [design.md](design.md)
- [docs/live_backend_contract.md](docs/live_backend_contract.md)
- [docs/LLM_PLAYBOOK.md](docs/LLM_PLAYBOOK.md)
- [docs/project_plan.md](docs/project_plan.md)
