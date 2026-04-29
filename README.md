# miku-shield

> **eBPF-based anti-Frida detection observer + mitigation for Android,
> built as a fork of [SeeFlowerX/stackplz](https://github.com/SeeFlowerX/stackplz)
> (Apache-2.0).**

`miku-shield` runs in **kernel-space**, *outside* the target process,
which means the apps you trace cannot detect the tooling itself — a
view that Frida-in-process injection can never give you. It plays the
mirror role to [traceMiku](https://github.com/ltlly/traceMiku) and the
patched `frida-server`: traceMiku captures instruction-level traces,
the patched server hides Frida's footprint inside the target process,
and `miku-shield` watches what the target *tries* to look at and
optionally short-circuits the most common file/socket-based detection
probes.

## Status

| Phase | What it does | Status |
|---|---|---|
| **Phase 1 — Identify** | Parse stackplz JSON syscall trace → emit anti-Frida detection timeline keyed by a YAML fingerprint library. | ✅ analyzer & detector library implemented + unit-tested; `analyze` subcommand works on captured traces; `identify` (live) wraps stackplz as a subprocess. |
| **Phase 2 — Mitigate (LSM)** | LSM `file_open` + `socket_connect` BPF programs that refuse open()/connect() on known frida paths/ports, scoped to the target UID. | 🟡 BPF program written, loader implemented, blocklist parser unit-tested. Loads on stock 5.10+ Android kernels; on the project's 4.19-cip128 backport currently hits a kernel-side LSM attach-id validation bug — see "Known kernel constraints" below. |
| **Phase 3 — /proc rewrite** | `fmod_ret` on `vfs_read` to scrub frida traces from `/proc/self/maps`, `/proc/self/status` (TracerPid), `/proc/self/task/*/comm`. | ⏳ deferred. |

## Layout

```
miku-shield/
├── README.md                       # this file (miku-shield additions)
├── UPSTREAM_README.md              # original stackplz README, preserved verbatim
├── LICENSE                         # Apache-2.0 (inherited from stackplz)
├── NOTICE                          # upstream attribution
├── docs/
│   └── ARCHITECTURE.md             # design notes for Phase 1+2
├── data/
│   └── known_detectors.yaml        # fingerprint database (paths, ports, /proc)
├── shield/                         # NEW — anti-Frida analysis layer (pure Go)
│   ├── db.go                       # YAML detector loader + index
│   ├── match.go                    # event-vs-detector matcher (incl. ** glob)
│   ├── pipeline.go                 # JSONL stream → Event → Detection
│   ├── sinks.go                    # PrettySink / JSONSink
│   ├── blocklist.go                # detector DB → kernel blocklist
│   ├── loader.go                   # Phase 2 LSM BPF object loader
│   └── *_test.go                   # 18 unit tests, all green
├── src/
│   ├── (stackplz BPF programs unchanged except small guard in syscall.c)
│   └── shield/
│       └── lsm_block.bpf.c         # NEW — Phase 2 LSM hooks
├── cli/cmd/
│   ├── root.go                     # stackplz default behaviour preserved
│   ├── shield.go                   # NEW — analyze / identify subcommands
│   └── mitigate.go                 # NEW — Phase 2 subcommand
└── user/
    ├── module/syscall.go           # patched: BTF fallback, optional fork probe
    ├── module/perf_mmap.go         # patched: BTF fallback
    └── util/btf_fallback.go        # NEW — load /mnt/vendor/persist/vmlinux.btf
```

## CLI

`miku-shield` keeps the original stackplz flag set as the no-subcommand
default, so any existing stackplz workflow keeps working. The new
subcommands are:

```
miku-shield analyze [FILE]       # offline analyse a stackplz JSON trace
miku-shield identify --pkg <pkg> # live capture: stackplz → analyzer
miku-shield mitigate --pkg <pkg> # Phase 2 LSM block (active on 5.10+ kernels)
```

### Quick start (offline — no device needed)

```bash
# 1. Capture a trace with stackplz on a 5.10+ device.
adb push miku-shield /data/local/tmp/
adb shell 'cd /data/local/tmp && ./miku-shield --btf -j -n com.taobao.taobao \
   --syscall openat,faccessat,connect,readlinkat -o /data/local/tmp/trace.jsonl'

# 2. Analyse it (host or device).
miku-shield analyze --output pretty /tmp/trace.jsonl
```

Sample output (synthetic JSONL fixture, real device output is identical
in shape):

```
miku-shield analyze  src=/tmp/sample.jsonl
─────────────────────────────────────────────────────────────────
[+ 0.000s] HIGH  frida-server-path         openat /data/local/tmp/frida-server
[+ 1.000s] MED   proc-self-maps-scan       openat /proc/self/maps
[+ 2.000s] HIGH  frida-default-port        connect 127.0.0.1:27042
─────────────────────────────────────────────────────────────────
total: 3 detections (high=2 med=1 low=0), 3 distinct detectors, 3 categories
by detector:
     1  frida-default-port
     1  frida-server-path
     1  proc-self-maps-scan
events: read=4 parsed=4 matched=3  span=3.000s
```

### Live capture

```bash
adb shell '/data/local/tmp/miku-shield identify --pkg com.taobao.taobao --duration 60'
```

`identify` spawns `./stackplz` as a subprocess and pipes its `--json`
output through the analyzer in-process. The default syscall whitelist
(`openat,faccessat,faccessat2,newfstatat,statx,readlinkat,connect`)
matches every syscall referenced by `data/known_detectors.yaml`.

### Mitigation

```bash
adb shell '/data/local/tmp/miku-shield mitigate --pkg com.taobao.taobao --duration 300'
```

The default blocklist is built automatically from `data/known_detectors.yaml`
(only `severity: high` entries with non-glob path strings or numeric
ports). Add ad-hoc entries with `--extra-path` / `--extra-port`.

## Known kernel constraints

This work was prototyped on the
[alioth-kernel-research](https://github.com/ltlly/alioth-kernel-research)
4.19-cip128 backport. The backport ships full mainline-grade
fentry / fexit / fmod_ret JIT support, but four constraints surfaced
while standing miku-shield up against it:

1. **`/sys/kernel/btf/vmlinux` not always exposed on slot _a.**
   `miku-shield` ships a fallback that loads
   `/mnt/vendor/persist/vmlinux.btf` directly via
   `btf.LoadSpec`. See `user/util/btf_fallback.go`. (verified working
   on the device — the BPF loader gets past the BTF lookup that
   upstream stackplz fails on.)

2. **`raw_tracepoint/sched_process_fork` rejected with `-EOPNOTSUPP`.**
   The probe is needed only for follow-fork syscall tracing, so it is
   compile-time gated (`-DMIKU_SHIELD_NO_FORK_TRACE` in the BPF C and
   `MIKU_SHIELD_FORK_TRACE=1` env to re-enable in builds without the
   guard).

3. **`raw_tracepoint/sys_enter` (stackplz's main syscall hook)
   verifier rejection.** stackplz's existing `src/syscall.c` relies on
   verifier behaviour that this 4.19 backport does not fully accept
   (~23k lines of verifier log, generic `EOPNOTSUPP`). Two workarounds
   exist today:
   - capture JSONL on a 5.10+ device, then feed it to `miku-shield analyze`.
   - re-flash the alioth-kernel-research project's newer slot _a
     (`g43c03d52ba05` and beyond) which has additional verifier fixes.

4. **`lsm/file_open` attach-id validation rejects the correct BTF id.**
   `cat /proc/kallsyms | grep bpf_lsm_file_open` shows the symbol is
   present, the BTF id resolves to a `BTF_KIND_FUNC` entry of name
   `bpf_lsm_file_open`, but the verifier fails with
   `points to wrong type name bpf_lsm_file_open`. Reproduced with a
   minimal `bpftool prog loadall` test, so it is a kernel-side issue
   and not a `cilium/ebpf` problem. Phase 2 mitigation therefore loads
   cleanly on stock 5.10+ Android kernels but cannot be exercised on
   this specific 4.19 build today.

The miku-shield code itself is BTF/CO-RE clean — the BPF objects are
compiled against `vmlinux.h` generated from the device's
`/mnt/vendor/persist/vmlinux.btf`, with a single warning
(`PT_REGS_PARM6` macro redefinition between bpf_tracing.h and stackplz's
own arch.h). The Go layer cross-compiles cleanly against NDK r29 +
Go 1.21+.

## Building

```bash
# host-only (analyze + tests)
go test ./shield/

# android-arm64 binary
export NDK_ROOT=$HOME/Android/Sdk/ndk/android-ndk-r29
export PATH=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

# 1. compile BPF objects
clang -D__TARGET_ARCH_arm64 -D__MODULE_SYSCALL -DMIKU_SHIELD_NO_FORK_TRACE \
      --target=bpf -c -nostdlibinc -no-canonical-prefixes -O2 \
      -I /usr/include/bpf -I src -g -o user/assets/syscall.o src/syscall.c
clang -D__TARGET_ARCH_arm64 \
      --target=bpf -c -nostdlibinc -no-canonical-prefixes -O2 \
      -I /usr/include/bpf -I src -g -o user/assets/perf_mmap.o src/perf_mmap.c
clang -D__TARGET_ARCH_arm64 -D__MODULE_STACK \
      --target=bpf -c -nostdlibinc -no-canonical-prefixes -O2 \
      -I /usr/include/bpf -I src -g -o user/assets/stack.o src/stack.c
clang --target=bpf -O2 -g -nostdlibinc -no-canonical-prefixes \
      -I /usr/include -I src/shield -c src/shield/lsm_block.bpf.c \
      -o user/assets/lsm_block.bpf.o

# 2. embed assets
go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets \
   -o assets/ebpf_probe.go \
   user/config/config_syscall_aarch64.json user/config/config_syscall_aarch32.json \
   user/assets/syscall.o user/assets/stack.o user/assets/perf_mmap.o \
   user/assets/lsm_block.bpf.o \
   preload_libs/libstackplz.so preload_libs/libstackplz10.so

# 3. cross-compile go
GOARCH=arm64 GOOS=android CGO_ENABLED=1 \
   CC=aarch64-linux-android29-clang \
   go build -ldflags "-w -s -extldflags '-Wl,--hash-style=sysv'" \
   -o bin/miku-shield .
```

The `vmlinux.h` used for the LSM BPF program is generated from a
specific kernel's BTF; for general use, regenerate against the BTF of
your target kernel:

```bash
adb pull /sys/kernel/btf/vmlinux /tmp/vmlinux  # or /mnt/vendor/persist/vmlinux.btf
bpftool btf dump file /tmp/vmlinux format c > src/shield/vmlinux.h
```

## Detector library

`data/known_detectors.yaml` is the seed fingerprint library. Each
entry has the shape:

```yaml
- id: frida-server-path           # stable kebab-case identifier
  severity: high                  # high | medium | low
  category: filesystem            # filesystem | network | proc | syscall
  summary: target probed Frida-server path
  match:                          # implicit-AND across keys
    syscall: [openat, faccessat]  # any-of
    path_glob:                    # any-of, supports * (within segment) and **
      - /data/local/tmp/frida-server*
```

Add a new detector by appending a YAML entry — the analyzer picks it up
on next run, no code changes needed. Glob support is intentionally
limited (the kernel-side blocklist for Phase 2 cannot enforce wildcards,
so wildcard entries are observed by identification but silent for
mitigation).

## Roadmap (open work)

- Strip the heavy stackplz syscall BPF program down to the subset
  needed for Phase 1 to bypass the 4.19 verifier rejection.
- Auto-derive the syscall whitelist for `identify` from
  `data/known_detectors.yaml` so trace volume stays minimal.
- Phase 3 `/proc` rewrite via `fmod_ret`+`bpf_probe_write_user`.
- CI: build BPF objects + run `go test ./shield/...` on every push.

## Credits

`miku-shield` is a fork of [SeeFlowerX/stackplz](https://github.com/SeeFlowerX/stackplz)
(Apache-2.0). All of stackplz's syscall / uprobe / hardware-breakpoint
trace machinery is reused; miku-shield contributes:

- the anti-Frida detection-pattern matching layer (`shield/`)
- the LSM-based mitigation BPF program + loader
- BTF fallback for kernels missing `/sys/kernel/btf/vmlinux`
- the new `analyze` / `identify` / `mitigate` subcommands

Original stackplz license lives unmodified at [LICENSE](LICENSE);
upstream attribution is in [NOTICE](NOTICE).

Author of stackplz: **SeeFlowerX**. Project URL:
https://github.com/SeeFlowerX/stackplz.
