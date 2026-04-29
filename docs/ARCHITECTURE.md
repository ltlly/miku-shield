# miku-shield architecture

> Phase 1 — anti-frida detection identifier (this document).
> Phase 2 — LSM-based mitigation (file_open / socket_connect deny).
> Phase 3 — fmod_ret-based /proc rewrite (deferred).

## Layering on top of stackplz

```
+---------------------------------------------------------------+
|                       cli/cmd/shield.go                       |
|       cobra subcommand: identify / analyze / mitigate         |
+--------+------------------------------------+-----------------+
         |                                    |
         v                                    v
+----------------+                    +----------------+
|  shield/spawn  |                    |   shield/db    |   YAML
|  (stackplz     |--- json events --->|  detectors     |<---- data/
|   subprocess)  |                    +-------+--------+   known_detectors.yaml
+----------------+                            |
         |                                    v
         |                            +-------+--------+
         +--- json events ----------->| shield/analyze |---> shield/timeline
                                      |  (matcher +    |     (text/json)
                                      |   classifier)  |
                                      +-------+--------+
                                              |
                                              v
                                      +-------+--------+
                                      |   stdout /     |
                                      |   --out file   |
                                      +----------------+
```

Phase 1 reuses stackplz's existing `syscall` BPF program (raw_syscalls
sys_enter / sys_exit tracepoints, with package-name → uid filtering and
JSON output via `--json`) by spawning the bundled binary as a subprocess.
The analyzer is a pure stdin → stdout filter, so it can also run on
captured trace files without a device.

## Detector database (`data/known_detectors.yaml`)

```yaml
version: 1
detectors:
  - id: frida-default-port
    severity: high
    category: network
    summary: connect() to frida-server default port 27042
    match:
      syscall: [connect]
      port: 27042

  - id: frida-server-path
    severity: high
    category: filesystem
    summary: openat() of frida-server binary path
    match:
      syscall: [openat, faccessat, faccessat2, statx, newfstatat]
      path_glob:
        - /data/local/tmp/frida-server*
        - /data/local/tmp/re.frida.server*
        - /data/local/tmp/.miku-srv          # traceMiku stealth-build path

  - id: proc-self-maps-scan
    severity: medium
    category: proc
    summary: target reading /proc/self/maps (likely module-name scan)
    match:
      syscall: [openat]
      path_exact: /proc/self/maps

  - id: tracerpid-status
    severity: medium
    category: proc
    summary: target reading /proc/self/status (TracerPid check)
    match:
      syscall: [openat]
      path_exact: /proc/self/status

  - id: thread-name-scan
    severity: medium
    category: proc
    summary: target enumerating /proc/self/task/<tid>/comm (frida thread-name scan)
    match:
      syscall: [openat]
      path_glob: /proc/self/task/*/comm
```

A detector's `match` block is implicit-AND. Within a single field with a
list (e.g. `path_glob: [...]`) it is OR. Multiple detectors can match the
same event — both are emitted.

## Event input schema

The analyzer accepts JSON-Lines from `stackplz --json -n <pkg> --syscall
openat,faccessat,connect,readlinkat,statx,newfstatat`. Each line is a
stackplz `SyscallEvent`. The analyzer extracts:

| field | source in stackplz JSON | use |
|---|---|---|
| `ts` | `boot_time` (uint64 ns; or seconds via `--showtime`) | timeline timestamp |
| `pid` | `pid` | grouping |
| `comm` | `comm` | display |
| `syscall` | `nr_name` | matcher input |
| `args[].name`/`value` | `args[]` | path/port extraction |
| `event` | `sys_enter` / `sys_exit` | only `sys_enter` is matched (Phase 1) |

For network syscalls (connect / sendto) the analyzer parses the
`sockaddr` argument bytes on its own to extract IPv4 / port, since
stackplz does not always render those.

## Timeline output

Pretty (default):

```
miku-shield identify  pkg=com.taobao.taobao  uid=10189
─────────────────────────────────────────────────────────
[+0.234s] HIGH  frida-default-port      connect 127.0.0.1:27042
[+0.456s] HIGH  frida-server-path       openat /data/local/tmp/frida-server
[+1.023s] MED   tracerpid-status        openat /proc/self/status
─────────────────────────────────────────────────────────
total: 3 detections, 2 distinct detectors, 2 categories
```

JSON (`--out json`): one JSON object per detection, plus a closing
summary record marked `{"event":"summary",...}`.

## Why a subprocess and not a tighter integration

- stackplz's CLI surface (`-n`, `-s`, `-j`, `-u`) already implements
  package-to-uid resolution, syscall whitelisting, and JSON event
  emission. Running it as a subprocess is no slower than calling it
  in-process and avoids touching `cli/cmd/root.go`.
- The analyzer becomes a pure stdin→stdout filter that can be
  unit-tested against fixture JSON, and can also analyse offline
  captures (`miku-shield analyze captured.jsonl`).
- Phase 2 (LSM mitigation) **will** add new BPF programs as a new
  stackplz module — that's a deeper change. Keeping Phase 1 cleanly
  layered on top of unmodified stackplz means upstream merges are safe.

## Phase 2 plan (sketch — implementation later)

- `src/shield/lsm_block.bpf.c` — `lsm/file_open` and `lsm/socket_connect`
  programs that consult two BPF hash maps (`shield_block_paths`,
  `shield_block_ports`) keyed by uid, return `-EACCES` / `-ECONNREFUSED`
  on hit.
- `user/module/shield_block.go` — Go module that loads the BPF object
  and pushes the path / port lists from the YAML detector DB at startup.
- `cli/cmd/shield.go` `--mitigate` flag enables the new module
  alongside the syscall trace.
