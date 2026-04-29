package shield

import (
	"bytes"
	"strings"
	"testing"
)

// Each line below is an actual-shape stackplz JSON event hand-built to
// exercise the analyzer. ts values are 1e9 apart so the timeline shows
// nice second offsets.
const fixtureJSONL = `{"event":"sys_enter","comm":"main","ts":1000000000,"pid":4292,"tid":4292,"uid":10189,"nr":56,"point_name":"openat","point_value":[{"arg_name":"dfd","arg_type":"int","arg_value":-100,"reg_index":0},{"arg_name":"filename","arg_type":"string","arg_value":"/data/local/tmp/frida-server","reg_index":1}]}
{"event":"sys_exit","comm":"main","ts":1000001000,"pid":4292,"tid":4292,"uid":10189,"nr":56,"point_name":"openat","point_value":[]}
{"event":"sys_enter","comm":"detect","ts":2000000000,"pid":4292,"tid":4310,"uid":10189,"nr":56,"point_name":"openat","point_value":[{"arg_name":"dfd","arg_type":"int","arg_value":-100,"reg_index":0},{"arg_name":"filename","arg_type":"string","arg_value":"/proc/self/maps","reg_index":1}]}
{"event":"sys_enter","comm":"detect","ts":3000000000,"pid":4292,"tid":4310,"uid":10189,"nr":203,"point_name":"connect","point_value":[{"arg_name":"fd","arg_type":"int","arg_value":42,"reg_index":0},{"arg_name":"uservaddr","arg_type":"sockaddr","arg_value":"0x7fff5be8c1f0(family=AF_INET, port=27042, addr=127.0.0.1)","reg_index":1}]}
{"event":"sys_enter","comm":"detect","ts":4000000000,"pid":4292,"tid":4310,"uid":10189,"nr":56,"point_name":"openat","point_value":[{"arg_name":"dfd","arg_type":"int","arg_value":-100,"reg_index":0},{"arg_name":"filename","arg_type":"string","arg_value":"/proc/self/task/4310/comm","reg_index":1}]}
{"event":"sys_enter","comm":"detect","ts":5000000000,"pid":4292,"tid":4310,"uid":10189,"nr":56,"point_name":"openat","point_value":[{"arg_name":"dfd","arg_type":"int","arg_value":-100,"reg_index":0},{"arg_name":"filename","arg_type":"string","arg_value":"/etc/hosts","reg_index":1}]}
`

func TestEventFromStackplzJSON_path(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(fixtureJSONL), "\n")
	ev, ok, err := EventFromStackplzJSON([]byte(lines[0]))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !ok {
		t.Fatalf("ok=false on sys_enter line")
	}
	if ev.Syscall != "openat" {
		t.Errorf("syscall=%q", ev.Syscall)
	}
	if ev.Path != "/data/local/tmp/frida-server" {
		t.Errorf("path=%q", ev.Path)
	}
	if ev.Pid != 4292 || ev.Uid != 10189 {
		t.Errorf("ids: pid=%d uid=%d", ev.Pid, ev.Uid)
	}
}

func TestEventFromStackplzJSON_skipsExit(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(fixtureJSONL), "\n")
	_, ok, err := EventFromStackplzJSON([]byte(lines[1]))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ok {
		t.Fatalf("ok=true for sys_exit (should skip)")
	}
}

func TestEventFromStackplzJSON_sockaddr(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(fixtureJSONL), "\n")
	// connect line is index 3
	ev, ok, err := EventFromStackplzJSON([]byte(lines[3]))
	if err != nil || !ok {
		t.Fatalf("decode: ok=%v err=%v", ok, err)
	}
	if ev.Syscall != "connect" {
		t.Errorf("syscall=%q", ev.Syscall)
	}
	if ev.Port != 27042 {
		t.Errorf("port=%d", ev.Port)
	}
	if ev.Addr != "127.0.0.1" {
		t.Errorf("addr=%q", ev.Addr)
	}
}

func TestAnalyzer_endToEnd(t *testing.T) {
	db, err := LoadDatabaseFile("../data/known_detectors.yaml")
	if err != nil {
		t.Fatalf("load detectors: %v", err)
	}
	var jsonOut bytes.Buffer
	a := &Analyzer{
		DB:   db,
		Sink: &JSONSink{W: &jsonOut},
	}
	if err := a.Run(strings.NewReader(fixtureJSONL)); err != nil {
		t.Fatalf("run: %v", err)
	}
	// Expect 4 detections + 1 summary line.
	gotLines := strings.Count(strings.TrimRight(jsonOut.String(), "\n"), "\n") + 1
	if gotLines < 4 {
		t.Fatalf("expected ≥4 output lines, got %d:\n%s", gotLines, jsonOut.String())
	}

	// Spot-check: the high-severity port and path detectors must fire.
	out := jsonOut.String()
	for _, want := range []string{"frida-default-port", "frida-server-path",
		"proc-self-maps-scan", "thread-name-scan"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected detector %q in output:\n%s", want, out)
		}
	}
	// /etc/hosts must NOT match any detector.
	if strings.Contains(out, "/etc/hosts") {
		t.Errorf("unexpected detector hit on /etc/hosts:\n%s", out)
	}

	if a.Stats.EventsRead != 6 {
		t.Errorf("read=%d want 6", a.Stats.EventsRead)
	}
	if a.Stats.EventsMatched != 4 {
		t.Errorf("matched=%d want 4", a.Stats.EventsMatched)
	}
}

func TestAnalyzer_pretty(t *testing.T) {
	db, err := LoadDatabaseFile("../data/known_detectors.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var w bytes.Buffer
	a := &Analyzer{
		DB:   db,
		Sink: &PrettySink{W: &w, Header: "test pkg=demo"},
	}
	if err := a.Run(strings.NewReader(fixtureJSONL)); err != nil {
		t.Fatalf("run: %v", err)
	}
	out := w.String()
	for _, want := range []string{"frida-default-port", "frida-server-path",
		"127.0.0.1:27042", "/proc/self/maps"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in pretty output:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "by detector:") {
		t.Errorf("missing summary block:\n%s", out)
	}
}

func TestAnalyzer_minSeverity(t *testing.T) {
	db, err := LoadDatabaseFile("../data/known_detectors.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var w bytes.Buffer
	a := &Analyzer{
		DB:          db,
		Sink:        &JSONSink{W: &w},
		MinSeverity: SeverityHigh,
	}
	if err := a.Run(strings.NewReader(fixtureJSONL)); err != nil {
		t.Fatalf("run: %v", err)
	}
	out := w.String()
	if strings.Contains(out, "proc-self-maps-scan") {
		t.Errorf("medium-severity detector leaked through high filter:\n%s", out)
	}
	if !strings.Contains(out, "frida-default-port") {
		t.Errorf("expected high detector to remain:\n%s", out)
	}
}
