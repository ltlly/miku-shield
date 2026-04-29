package shield

import (
	"strings"
	"testing"
)

const testYAML = `
version: 1
detectors:
  - id: frida-server-path
    severity: high
    category: filesystem
    summary: target probed Frida-server path
    match:
      syscall: [openat, faccessat]
      path_glob:
        - /data/local/tmp/frida-server*
        - /data/local/tmp/.miku-srv*

  - id: frida-default-port
    severity: high
    category: network
    summary: connect to 27042
    match:
      syscall: [connect]
      port: 27042

  - id: thread-name-scan
    severity: medium
    category: proc
    summary: thread comm scan
    match:
      syscall: [openat]
      path_glob:
        - /proc/self/task/*/comm

  - id: maps-scan
    severity: medium
    category: proc
    summary: read /proc/self/maps
    match:
      syscall: [openat]
      path_exact: /proc/self/maps
`

func loadTestDB(t *testing.T) *Database {
	t.Helper()
	db, err := LoadDatabase(strings.NewReader(testYAML))
	if err != nil {
		t.Fatalf("LoadDatabase: %v", err)
	}
	if got, want := len(db.Detectors), 4; got != want {
		t.Fatalf("detector count: got %d want %d", got, want)
	}
	return db
}

func TestLoadDatabase_versionRequired(t *testing.T) {
	_, err := LoadDatabase(strings.NewReader("detectors: []\n"))
	if err == nil {
		t.Fatalf("expected error on missing version")
	}
}

func TestLoadDatabase_duplicateID(t *testing.T) {
	_, err := LoadDatabase(strings.NewReader(`
version: 1
detectors:
  - id: dup
    severity: high
    category: filesystem
    summary: ""
    match:
      syscall: [openat]
      path_exact: /a
  - id: dup
    severity: high
    category: filesystem
    summary: ""
    match:
      syscall: [openat]
      path_exact: /b
`))
	if err == nil {
		t.Fatalf("expected duplicate-id error")
	}
}

func TestLoadDatabase_severityParsed(t *testing.T) {
	db := loadTestDB(t)
	for _, d := range db.Detectors {
		if d.parsedSeverity == 0 && d.Severity != "low" {
			// SeverityLow is the zero value; only acceptable when
			// the detector's source severity actually says low.
			t.Errorf("detector %s severity not parsed", d.ID)
		}
	}
}

func TestMatch_pathGlob(t *testing.T) {
	db := loadTestDB(t)

	cases := []struct {
		name string
		ev   Event
		want []string // expected detector ids in order
	}{
		{
			name: "frida-server exact path",
			ev:   Event{Syscall: "openat", Path: "/data/local/tmp/frida-server"},
			want: []string{"frida-server-path"},
		},
		{
			name: "frida-server with version suffix",
			ev:   Event{Syscall: "openat", Path: "/data/local/tmp/frida-server-17.9.1"},
			want: []string{"frida-server-path"},
		},
		{
			name: "miku-srv path",
			ev:   Event{Syscall: "faccessat", Path: "/data/local/tmp/.miku-srv"},
			want: []string{"frida-server-path"},
		},
		{
			name: "miku-srv with version suffix",
			ev:   Event{Syscall: "openat", Path: "/data/local/tmp/.miku-srv-17"},
			want: []string{"frida-server-path"},
		},
		{
			name: "wrong syscall",
			ev:   Event{Syscall: "read", Path: "/data/local/tmp/frida-server"},
			want: nil,
		},
		{
			name: "thread-name scan via task glob",
			ev:   Event{Syscall: "openat", Path: "/proc/self/task/12345/comm"},
			want: []string{"thread-name-scan"},
		},
		{
			name: "task glob misses non-comm path",
			ev:   Event{Syscall: "openat", Path: "/proc/self/task/12345/status"},
			want: nil,
		},
		{
			name: "exact maps path",
			ev:   Event{Syscall: "openat", Path: "/proc/self/maps"},
			want: []string{"maps-scan"},
		},
		{
			name: "no path means no path-based detection",
			ev:   Event{Syscall: "openat", Path: ""},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := db.Match(tc.ev)
			gotIDs := make([]string, len(got))
			for i, d := range got {
				gotIDs[i] = d.Detector.ID
			}
			if !sliceEq(gotIDs, tc.want) {
				t.Errorf("ids: got %v want %v", gotIDs, tc.want)
			}
		})
	}
}

func TestMatch_port(t *testing.T) {
	db := loadTestDB(t)

	cases := []struct {
		name string
		ev   Event
		want []string
	}{
		{"27042", Event{Syscall: "connect", Port: 27042}, []string{"frida-default-port"}},
		{"different port", Event{Syscall: "connect", Port: 8080}, nil},
		{"port without connect", Event{Syscall: "openat", Port: 27042}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := db.Match(tc.ev)
			gotIDs := make([]string, len(got))
			for i, d := range got {
				gotIDs[i] = d.Detector.ID
			}
			if !sliceEq(gotIDs, tc.want) {
				t.Errorf("ids: got %v want %v", gotIDs, tc.want)
			}
		})
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, target string
		want            bool
	}{
		{"/data/local/tmp/frida-server", "/data/local/tmp/frida-server", true},
		{"/data/local/tmp/frida-server*", "/data/local/tmp/frida-server", true},
		{"/data/local/tmp/frida-server*", "/data/local/tmp/frida-server-17", true},
		{"/data/local/tmp/frida-server*", "/data/local/tmp/frida-other", false},
		{"/proc/self/task/*/comm", "/proc/self/task/123/comm", true},
		{"/proc/self/task/*/comm", "/proc/self/task/123/status", false},
		{"/proc/self/task/*/comm", "/proc/self/task/123/sub/comm", false},
		{"/proc/**", "/proc/123/maps", true},
		{"/proc/**", "/proc/self/task/123/comm", true},
		{"/proc/**", "/etc/passwd", false},
	}
	for _, tc := range cases {
		got := globMatch(tc.pattern, tc.target)
		if got != tc.want {
			t.Errorf("glob(%q, %q) = %v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
