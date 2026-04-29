package shield

// Phase 2 — LSM-based mitigation BPF loader.
//
// The userspace counterpart of src/shield/lsm_block.bpf.c.  Loads the
// embedded BPF object, populates two block-lists from the YAML
// detector library, attaches the LSM probes, and waits.

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// PathKeyLen mirrors PATH_KEY_LEN in lsm_block.bpf.c.  Userspace pads
// every blocklist entry with NUL bytes up to this length so the lookup
// in the BPF program (which uses the same fixed-size key) succeeds.
const PathKeyLen = 240

// MitigationConfig drives Loader.Apply.
type MitigationConfig struct {
	// TargetUID is patched into the BPF program's .rodata before
	// loading so the LSM hooks short-circuit for every other UID.
	// Use 0 to apply the mitigation system-wide (NOT recommended on
	// real devices).
	TargetUID uint32

	// BlockPaths is the absolute-path blocklist applied to file_open.
	// Entries longer than PathKeyLen are silently truncated.
	BlockPaths []string

	// BlockPorts is the TCP port blocklist applied to socket_connect.
	BlockPorts []uint16
}

// Stats mirrors struct shield_stats in the BPF program.
type Stats struct {
	FileOpenChecked    uint64
	FileOpenBlocked    uint64
	SockConnectChecked uint64
	SockConnectBlocked uint64
}

// Loader holds the in-memory state of an active mitigation session.
type Loader struct {
	objectBytes  []byte
	kernelBTF    *btf.Spec
	collection   *ebpf.Collection
	links        []link.Link
	statsMap     *ebpf.Map
	pathsMap     *ebpf.Map
	portsMap     *ebpf.Map
	scratchMap   *ebpf.Map

	mu sync.Mutex
}

// NewLoader prepares (but does not yet apply) a mitigation session
// from a BPF object reader. The kernel BTF spec is optional — if nil,
// cilium/ebpf will look it up under /sys/kernel/btf/vmlinux.
func NewLoader(obj io.Reader, kernelBTF *btf.Spec) (*Loader, error) {
	objBytes, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("read bpf object: %w", err)
	}
	return &Loader{
		objectBytes: objBytes,
		kernelBTF:   kernelBTF,
	}, nil
}

// Apply loads the BPF object, populates the maps, attaches the LSM
// probes, and returns. The caller must call Close to detach.
func (l *Loader) Apply(cfg MitigationConfig) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.collection != nil {
		return errors.New("Loader.Apply: already applied")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(byteReader(l.objectBytes))
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"TARGET_UID": cfg.TargetUID,
	}); err != nil {
		return fmt.Errorf("rewrite TARGET_UID: %w", err)
	}

	collOpts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize:     2 * 1024 * 1024,
			KernelTypes: l.kernelBTF,
		},
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, collOpts)
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}
	l.collection = coll

	// Cache map handles.
	if l.pathsMap = coll.Maps["shield_block_paths"]; l.pathsMap == nil {
		l.unsafeClose()
		return errors.New("missing map shield_block_paths in object")
	}
	if l.portsMap = coll.Maps["shield_block_ports"]; l.portsMap == nil {
		l.unsafeClose()
		return errors.New("missing map shield_block_ports in object")
	}
	if l.scratchMap = coll.Maps["shield_scratch"]; l.scratchMap == nil {
		l.unsafeClose()
		return errors.New("missing map shield_scratch in object")
	}
	l.statsMap = coll.Maps["shield_stats_map"]

	// Populate path blocklist.
	for _, p := range cfg.BlockPaths {
		var key [PathKeyLen]byte
		// Path strings are ASCII; non-ASCII bytes still fit byte-wise.
		copy(key[:], p)
		var v uint8 = 1
		if err := l.pathsMap.Update(&key, &v, ebpf.UpdateAny); err != nil {
			l.unsafeClose()
			return fmt.Errorf("update shield_block_paths[%q]: %w", p, err)
		}
	}

	// Populate port blocklist.
	for _, port := range cfg.BlockPorts {
		var v uint8 = 1
		if err := l.portsMap.Update(&port, &v, ebpf.UpdateAny); err != nil {
			l.unsafeClose()
			return fmt.Errorf("update shield_block_ports[%d]: %w", port, err)
		}
	}

	// Attach every LSM program present in the BPF object. Programs
	// that the BPF C source has compiled-out (e.g. socket_connect on
	// kernels where the LSM hook isn't attachable) are silently
	// skipped — the corresponding map population above is a no-op
	// when the program is missing.
	attached := 0
	for _, name := range []string{"shield_file_open", "shield_socket_connect"} {
		prog := coll.Programs[name]
		if prog == nil {
			continue
		}
		lk, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			l.unsafeClose()
			return fmt.Errorf("attach LSM %s: %w", name, err)
		}
		l.links = append(l.links, lk)
		attached++
	}
	if attached == 0 {
		l.unsafeClose()
		return errors.New("no LSM programs attached — check lsm_block.bpf.o build flags")
	}

	return nil
}

// Stats returns a snapshot of the mitigation hit counters.
func (l *Loader) Stats() (Stats, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.statsMap == nil {
		return Stats{}, errors.New("Loader.Stats: not applied")
	}
	var z uint32 = 0
	cpuCount, err := perCPUValueLen(l.statsMap)
	if err != nil {
		return Stats{}, err
	}
	values := make([]Stats, cpuCount)
	if err := l.statsMap.Lookup(&z, &values); err != nil {
		// PerCPU only when the map was created PERCPU; ours is plain
		// ARRAY so a single Lookup works.
		var v Stats
		if e2 := l.statsMap.Lookup(&z, &v); e2 != nil {
			return Stats{}, fmt.Errorf("stats lookup: %w / %w", err, e2)
		}
		return v, nil
	}
	var agg Stats
	for _, v := range values {
		agg.FileOpenChecked += v.FileOpenChecked
		agg.FileOpenBlocked += v.FileOpenBlocked
		agg.SockConnectChecked += v.SockConnectChecked
		agg.SockConnectBlocked += v.SockConnectBlocked
	}
	return agg, nil
}

// Close detaches the LSM probes and frees BPF resources.
func (l *Loader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.unsafeClose()
}

func (l *Loader) unsafeClose() error {
	var firstErr error
	for _, lk := range l.links {
		if err := lk.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	l.links = nil
	if l.collection != nil {
		l.collection.Close()
		l.collection = nil
	}
	return firstErr
}

func perCPUValueLen(m *ebpf.Map) (int, error) {
	switch m.Type() {
	case ebpf.PerCPUArray, ebpf.PerCPUHash, ebpf.LRUCPUHash:
		// Cilium reads the per-CPU count from /sys/devices/.../possible
		// internally; we approximate by 1 here and let the lookup fail
		// loudly so the fallback path runs.
		return 1, nil
	}
	return 0, errPerCPUNotSupported
}

var errPerCPUNotSupported = errors.New("map type is not per-cpu")

// byteReader is a tiny io.ReaderAt-backed bytes.Reader replacement
// that avoids pulling bytes into closures repeatedly.
func byteReader(b []byte) *byteReaderImpl {
	return &byteReaderImpl{b: b}
}

type byteReaderImpl struct {
	b []byte
	i int
}

func (r *byteReaderImpl) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func (r *byteReaderImpl) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (r *byteReaderImpl) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		r.i = int(offset)
	case io.SeekCurrent:
		r.i += int(offset)
	case io.SeekEnd:
		r.i = len(r.b) + int(offset)
	}
	return int64(r.i), nil
}

// keep time imported when we add stats polling helpers
var _ = time.Second
