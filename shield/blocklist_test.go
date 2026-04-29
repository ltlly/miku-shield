package shield

import (
	"strings"
	"testing"
)

func TestBlocklistFromDB_excludesGlobsAndLowSev(t *testing.T) {
	yaml := `
version: 1
detectors:
  - id: frida-server-path
    severity: high
    category: filesystem
    summary: ""
    match:
      syscall: [openat]
      path_glob:
        - /data/local/tmp/frida-server*       # glob — must be dropped
        - /data/local/tmp/.miku-srv           # exact — kept

  - id: frida-default-port
    severity: high
    category: network
    summary: ""
    match:
      syscall: [connect]
      port: 27042

  - id: low-sig
    severity: low
    category: filesystem
    summary: ""
    match:
      syscall: [openat]
      path_exact: /tmp/should-be-skipped
`
	db, err := LoadDatabase(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Mitigation matches on the leaf component (basename), not the
	// full path — see BlocklistFromDB doc.
	paths, ports := BlocklistFromDB(db)
	wantLeaf := ".miku-srv"
	if len(paths) != 1 || paths[0] != wantLeaf {
		t.Errorf("paths got %v want [%q]", paths, wantLeaf)
	}
	if len(ports) != 1 || ports[0] != 27042 {
		t.Errorf("ports got %v want [27042]", ports)
	}
}
