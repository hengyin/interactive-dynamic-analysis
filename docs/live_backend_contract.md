# Live Backend Contract

This document defines the minimum phase-1 contract for a real `qemu-user` backend integration.

## Overview

The runtime expects three moving parts:

1. A target binary
2. An event stream endpoint
3. An RPC endpoint

The runtime may either:

- attach to already-running endpoints
- or launch `qemu-user` itself and then attach to the endpoints

## Environment

When the runtime launches `qemu-user`, it will set:

- `IA_EVENT_SOCKET`
- `IA_RPC_SOCKET`

Your instrumentation side should use those values to know where to publish events and where to serve RPC.

## Transport

Phase 1 uses two separate newline-delimited JSON channels over Unix sockets.

### Event channel

Direction:

- instrumentation -> runtime

Each line is one event object.

Example:

```json
{"event_id":"e-1","seq":1,"type":"branch","timestamp":1.0,"pc":"0x401000","thread_id":"1","cpu_id":null,"payload":{"target":"0x401010","taken":true}}
```

### RPC channel

Direction:

- runtime -> instrumentation
- instrumentation -> runtime

Request shape:

```json
{"id":1,"method":"get_registers","params":{"names":["rax","rip"]}}
```

Response shape:

```json
{"id":1,"result":{"registers":{"rax":"0x1","rip":"0x401000"}}}
```

Error response:

```json
{"id":1,"error":{"message":"unsupported method"}}
```

## Required RPC Methods

### `resume`

Request:

```json
{"id":1,"method":"resume","params":{}}
```

Response:

```json
{"id":1,"result":{}}
```

### `pause`

Same envelope as `resume`.

### `query_status`

Response:

```json
{"id":1,"result":{"status":"paused"}}
```

Allowed status values for phase 1:

- `idle`
- `running`
- `paused`
- `stopped`
- `exited`

### `get_registers`

Response:

```json
{"id":1,"result":{"registers":{"rip":"0x401000","rsp":"0x7fffffffe000"}}}
```

Rules:

- register names are strings
- register values are strings
- hex values should use `0x` form when applicable

### `read_memory`

Request:

```json
{"id":1,"method":"read_memory","params":{"address":"0x401000","size":16}}
```

Response:

```json
{"id":1,"result":{"address":"0x401000","size":16,"bytes":"554889e5..."}}
```

Rules:

- `bytes` is a lowercase hex string
- max size in phase 1 is 256 bytes

### `list_memory_maps`

Response:

```json
{
  "id": 1,
  "result": {
    "regions": [
      {
        "start": "0x400000",
        "end": "0x401000",
        "perm": "r-x",
        "name": "/path/to/target"
      }
    ]
  }
}
```

## Event Production Rules

- `seq` must increase monotonically within a session
- `pc` must be present when meaningful
- events should be filtered enough to remain usable
- block-level and branch-level events are preferred defaults
- instruction-level firehoses should be avoided in phase 1

## Startup Expectations

If the runtime is in launch mode:

1. it starts `qemu-user`
2. it expects the instrumentation side to create/connect the event and RPC sockets
3. it then connects clients to those sockets

If the runtime is in attach mode:

1. the instrumentation endpoints already exist
2. the runtime only connects to them

## Minimal Success Criteria

A valid live backend integration for phase 1 should support:

- `resume`
- `pause`
- `query_status`
- `get_registers`
- `read_memory`
- `list_memory_maps`
- one or more useful execution event types such as `basic_block` or `branch`

## Recommended Readiness Handshake

The instrumentation side should emit a readiness event as soon as it is attached and able to serve RPC plus events.

Recommended event:

```json
{
  "event_id": "e-1",
  "seq": 1,
  "type": "backend_ready",
  "timestamp": 1710000000.0,
  "pc": null,
  "thread_id": null,
  "cpu_id": null,
  "payload": {
    "status": "attached"
  }
}
```

This lets the runtime or demo wait for a meaningful attachment signal rather than assuming that socket creation alone implies readiness.
