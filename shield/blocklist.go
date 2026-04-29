package shield

import "strings"

// BlocklistFromDB pulls (paths, ports) suitable for Phase 2 LSM
// mitigation out of the YAML detector library.
//
// Path entries that contain glob wildcards are dropped — the kernel-
// side hash map matches on exact byte-equal keys, so a glob-form like
// `/data/local/tmp/frida-server*` cannot be enforced via this map. The
// caller can instrument those paths separately (e.g. via Phase 3
// fmod_ret on vfs_read).
//
// Path entries longer than PathKeyLen are truncated; the caller is
// responsible for ensuring the truncated prefix is unambiguous.
func BlocklistFromDB(db *Database) (paths []string, ports []uint16) {
	if db == nil {
		return nil, nil
	}
	seenPath := map[string]bool{}
	seenPort := map[uint16]bool{}
	for _, d := range db.Detectors {
		if d.parsedSeverity < SeverityHigh {
			// Mitigation is opt-in only for high-confidence
			// signals — medium signals are noisy enough that
			// blocking them tends to break the host app.
			continue
		}
		if d.Match.PathExact != "" && !seenPath[d.Match.PathExact] {
			paths = append(paths, truncatePath(d.Match.PathExact))
			seenPath[d.Match.PathExact] = true
		}
		for _, g := range d.Match.PathGlob {
			if strings.ContainsAny(g, "*?[") {
				continue
			}
			if seenPath[g] {
				continue
			}
			paths = append(paths, truncatePath(g))
			seenPath[g] = true
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
	return paths, ports
}

func truncatePath(p string) string {
	if len(p) >= PathKeyLen {
		return p[:PathKeyLen-1]
	}
	return p
}
