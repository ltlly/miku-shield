package shield

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

// stackplzEnvelope is just enough of the stackplz JSON event shape for
// the analyzer to extract a path or sockaddr-port out of any single
// sys_enter line. Fields we don't need are left as raw bytes.
type stackplzEnvelope struct {
	Event      string         `json:"event"`
	Comm       string         `json:"comm"`
	Ts         uint64         `json:"ts"`
	Pid        uint32         `json:"pid"`
	Tid        uint32         `json:"tid"`
	Uid        uint32         `json:"uid"`
	NR         uint32         `json:"nr"`
	PointName  string         `json:"point_name"`
	PointValue []stackplzArg  `json:"point_value"`
}

type stackplzArg struct {
	ArgName  string          `json:"arg_name"`
	ArgType  string          `json:"arg_type"`
	ArgValue json.RawMessage `json:"arg_value"`
	RegIndex uint32          `json:"reg_index"`
}

// Sockaddr argument values arrive as something like:
//
//	"0x7fff5be8c1f0(family=AF_INET, port=27042, addr=127.0.0.1)"
//
// The format is produced by argtype.parse_SOCKADDR; we extract the two
// fields we care about with a regex rather than re-decoding binary.
var (
	reSockPort = regexp.MustCompile(`port=(\d+)`)
	reSockAddr = regexp.MustCompile(`addr=([^,)]+)`)
)

// EventFromStackplzJSON converts one stackplz JSON event line into the
// analyzer's normalised Event. Returns ok=false when the line is not a
// sys_enter syscall (sys_exit, fork, mmap2, etc. are skipped).
func EventFromStackplzJSON(line []byte) (Event, bool, error) {
	var env stackplzEnvelope
	if err := json.Unmarshal(line, &env); err != nil {
		return Event{}, false, fmt.Errorf("decode envelope: %w", err)
	}
	if env.Event != "sys_enter" {
		return Event{}, false, nil
	}
	ev := Event{
		Ts:      env.Ts,
		Pid:     env.Pid,
		Tid:     env.Tid,
		Uid:     env.Uid,
		Comm:    env.Comm,
		Syscall: env.PointName,
		Raw:     line,
	}

	// Walk args once, picking out the most relevant value.
	for _, a := range env.PointValue {
		switch a.ArgType {
		case "string":
			// stackplz writes arg_value as a JSON string for
			// path-typed arguments.
			var s string
			if err := json.Unmarshal(a.ArgValue, &s); err == nil && s != "" {
				if ev.Path == "" || a.ArgName == "filename" || a.ArgName == "pathname" {
					ev.Path = s
				}
			}
		case "sockaddr":
			var s string
			if err := json.Unmarshal(a.ArgValue, &s); err != nil {
				continue
			}
			if m := reSockPort.FindStringSubmatch(s); len(m) == 2 {
				if v, err := strconv.ParseUint(m[1], 10, 32); err == nil {
					ev.Port = uint32(v)
				}
			}
			if m := reSockAddr.FindStringSubmatch(s); len(m) == 2 {
				ev.Addr = m[1]
			}
		}
	}
	return ev, true, nil
}

// Analyzer streams JSON event lines through the detector database and
// writes detection records to a Sink.
type Analyzer struct {
	DB   *Database
	Sink Sink

	// MinSeverity drops detections strictly below this severity.
	MinSeverity Severity

	// Stats — populated as events flow.
	Stats AnalyzerStats
}

// AnalyzerStats summarises what the analyzer saw.
type AnalyzerStats struct {
	EventsRead      int
	EventsParsed    int
	EventsMatched   int
	DetectionsHigh  int
	DetectionsMed   int
	DetectionsLow   int
	DetectorHits    map[string]int
	CategoryHits    map[string]int
	FirstTs, LastTs uint64
}

func (s *AnalyzerStats) record(d Detection) {
	if s.DetectorHits == nil {
		s.DetectorHits = map[string]int{}
		s.CategoryHits = map[string]int{}
	}
	s.DetectorHits[d.Detector.ID]++
	s.CategoryHits[d.Detector.Category]++
	switch d.Detector.parsedSeverity {
	case SeverityHigh:
		s.DetectionsHigh++
	case SeverityMedium:
		s.DetectionsMed++
	case SeverityLow:
		s.DetectionsLow++
	}
}

// Run reads JSONL from r, runs every parsed event through the database,
// and emits detections to the sink. Lines that fail to parse are
// skipped (with a count exposed via Stats).
func (a *Analyzer) Run(r io.Reader) error {
	if a.DB == nil {
		return fmt.Errorf("Analyzer.Run: nil DB")
	}
	if a.Sink == nil {
		a.Sink = discardSink{}
	}
	if err := a.Sink.Begin(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for scanner.Scan() {
		a.Stats.EventsRead++
		line := append([]byte(nil), scanner.Bytes()...)
		ev, ok, err := EventFromStackplzJSON(line)
		if err != nil || !ok {
			continue
		}
		a.Stats.EventsParsed++
		if a.Stats.FirstTs == 0 || ev.Ts < a.Stats.FirstTs {
			a.Stats.FirstTs = ev.Ts
		}
		if ev.Ts > a.Stats.LastTs {
			a.Stats.LastTs = ev.Ts
		}
		hits := a.DB.Match(ev)
		if len(hits) == 0 {
			continue
		}
		a.Stats.EventsMatched++
		for _, h := range hits {
			if h.Detector.parsedSeverity < a.MinSeverity {
				continue
			}
			a.Stats.record(h)
			if err := a.Sink.OnDetection(h); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	return a.Sink.End(a.Stats)
}

// Sink consumes detections.  Implementations live in sinks.go.
type Sink interface {
	Begin() error
	OnDetection(Detection) error
	End(AnalyzerStats) error
}

type discardSink struct{}

func (discardSink) Begin() error                { return nil }
func (discardSink) OnDetection(Detection) error { return nil }
func (discardSink) End(AnalyzerStats) error     { return nil }
