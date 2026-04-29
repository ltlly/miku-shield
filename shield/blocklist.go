package shield

import (
	"path"
	"strings"
)

// BlocklistFromDB pulls (basenames, ports) suitable for Phase 2 LSM
// mitigation out of the YAML detector library.
//
// The kernel-side LSM file_open hook in lsm_block.bpf.c matches on the
// **leaf component** of the file's path (file->f_path.dentry->d_name),
// not on the full absolute path.  This is intentional:
//
//   - bpf_d_path is restricted by an empty BTF_SET allowlist on 4.19
//     backports, so calling it from an LSM program is rejected.
//   - Every anti-Frida signature path we care about has a *unique*
//     leaf (`frida-server`, `frida-cli`, `.miku-srv`, ...).  Globs in
//     the YAML library like `/data/local/tmp/frida-server*` are
//     reduced to their leaf prefix — when a literal `*` follows the
//     wildcard, we keep the prefix portion of the leaf so userspace
//     can still emit a stable key.  However, the kernel-side map is
//     an exact-byte hash, so a leaf with a trailing `*` cannot match.
//
// Returns:
//   leafs: zero-or-more LEAF basenames suitable for shield_block_paths
//          map keys.  Caller pads to PathKeyLen with zeros.
//   ports: zero-or-more TCP/UDP ports for shield_block_ports.
func BlocklistFromDB(db *Database) (leafs []string, ports []uint16) {
	if db == nil {
		return nil, nil
	}
	seenLeaf := map[string]bool{}
	seenPort := map[uint16]bool{}
	addLeaf := func(p string) {
		l := pathLeaf(p)
		if l == "" || strings.ContainsAny(l, "*?[") {
			return
		}
		if seenLeaf[l] {
			return
		}
		leafs = append(leafs, l)
		seenLeaf[l] = true
	}
	for _, d := range db.Detectors {
		if d.parsedSeverity < SeverityHigh {
			// Mitigation is opt-in only for high-confidence
			// signals — medium signals are noisy enough that
			// blocking them tends to break the host app.
			continue
		}
		if d.Match.PathExact != "" {
			addLeaf(d.Match.PathExact)
		}
		for _, g := range d.Match.PathGlob {
			addLeaf(g)
		}
		for _, p := range d.Match.Port {
			port := uint16(p)
			if seenPort[port] {
				continue
			}
			ports = append(ports, port)
			seenPort[port] = true
		}
	}
	return leafs, ports
}

// pathLeaf returns the last path component of an absolute (or relative)
// path, dropping any trailing slashes.  Wildcard characters in the leaf
// are preserved here; the caller is responsible for filtering them out.
func pathLeaf(p string) string {
	if p == "" {
		return ""
	}
	return path.Base(p)
}
