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
	paths, ports := BlocklistFromDB(db)
	wantPath := "/data/local/tmp/.miku-srv"
	if len(paths) != 1 || paths[0] != wantPath {
		t.Errorf("paths got %v want [%q]", paths, wantPath)
	}
	if len(ports) != 1 || ports[0] != 27042 {
		t.Errorf("ports got %v want [27042]", ports)
	}
}
