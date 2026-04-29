# miku-shield real-target reports

Each report here is the output of running `miku-shield` (or its bundled
stackplz with the matching detector library at `data/known_detectors.yaml`)
against a real Android app running on a real device.

| date       | target package          | tag        | report                    |
|------------|-------------------------|------------|---------------------------|
| 2026-04-30 | `com.taobao.taobao`     | TB         | [tb-2026-04-30.md](tb-2026-04-30.md) |
| 2026-04-30 | `com.Qunar`             | Qunar (去哪儿) | [qunar-2026-04-30.md](qunar-2026-04-30.md) |

## Methodology (common to all reports)

```
device   : Xiaomi alioth (Redmi K40), kernel g79a70a234c00 (4.19-cip128 + JIT fixes)
trace    : stackplz (the miku-shield single-binary fork) running with
           --syscall openat,connect,readlinkat,faccessat,newfstatat,statx,
                     prctl,ptrace,mprotect,pread64
filter   : -u <appUid>   (uid filter — captures every process running
                          under the target's uid, including Runtime.exec
                          subprocesses)
attach   : *before* the app starts.  stackplz waits 2 s for BPF attach,
           then `am start -W` cold-launches the app.  This catches
           detection probes that fire in the first ~100 ms of process
           lifetime, which a post-launch attach misses.
analyzer : `miku-shield analyze --output pretty`, with the YAML detector
           library at `data/known_detectors.yaml`
output   : JSON-Lines (raw events) + pretty-printed detection timeline
```

These reports are working notes, not stable claims.  The detector
library is a moving target — see `git log -- data/known_detectors.yaml`.
