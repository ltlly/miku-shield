package shield

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// PrettySink renders a one-line-per-detection text timeline to w.
//
// Format:
//
//	[+0.234s] HIGH  frida-default-port      connect 127.0.0.1:27042
//	[+0.456s] HIGH  frida-server-path       openat /data/local/tmp/frida-server
//	─────────────────────────────────────────────────────────
//	total: 3 detections, 2 distinct detectors, 2 categories
type PrettySink struct {
	W            io.Writer
	HeaderShown  bool
	Header       string // optional one-line preamble
	originStamp  uint64
}

func (p *PrettySink) Begin() error {
	if p.Header != "" {
		fmt.Fprintln(p.W, p.Header)
	}
	fmt.Fprintln(p.W, "─────────────────────────────────────────────────────────────────")
	return nil
}

func (p *PrettySink) OnDetection(d Detection) error {
	if p.originStamp == 0 {
		p.originStamp = d.Event.Ts
	}
	rel := relSeconds(d.Event.Ts, p.originStamp)
	descr := describeEvent(d.Event)
	_, err := fmt.Fprintf(p.W, "[+%6.3fs] %s  %-24s  %s\n",
		rel, d.Detector.parsedSeverity.Label(), d.Detector.ID, descr)
	return err
}

func (p *PrettySink) End(s AnalyzerStats) error {
	fmt.Fprintln(p.W, "─────────────────────────────────────────────────────────────────")
	fmt.Fprintf(p.W, "total: %d detections (high=%d med=%d low=%d), %d distinct detectors, %d categories\n",
		s.DetectionsHigh+s.DetectionsMed+s.DetectionsLow,
		s.DetectionsHigh, s.DetectionsMed, s.DetectionsLow,
		len(s.DetectorHits), len(s.CategoryHits))
	if len(s.DetectorHits) > 0 {
		ids := make([]string, 0, len(s.DetectorHits))
		for k := range s.DetectorHits {
			ids = append(ids, k)
		}
		sort.Slice(ids, func(i, j int) bool {
			if s.DetectorHits[ids[i]] != s.DetectorHits[ids[j]] {
				return s.DetectorHits[ids[i]] > s.DetectorHits[ids[j]]
			}
			return ids[i] < ids[j]
		})
		fmt.Fprintln(p.W, "by detector:")
		for _, id := range ids {
			fmt.Fprintf(p.W, "  %4d  %s\n", s.DetectorHits[id], id)
		}
	}
	fmt.Fprintf(p.W, "events: read=%d parsed=%d matched=%d  span=%.3fs\n",
		s.EventsRead, s.EventsParsed, s.EventsMatched,
		relSeconds(s.LastTs, s.FirstTs))
	return nil
}

func describeEvent(e Event) string {
	switch e.Syscall {
	case "connect":
		if e.Addr != "" {
			return fmt.Sprintf("connect %s:%d", e.Addr, e.Port)
		}
		return fmt.Sprintf("connect port=%d", e.Port)
	default:
		if e.Path != "" {
			return fmt.Sprintf("%s %s", e.Syscall, e.Path)
		}
		return e.Syscall
	}
}

func relSeconds(now, origin uint64) float64 {
	if origin == 0 || now < origin {
		return 0
	}
	const nsPerSec = 1e9
	return float64(now-origin) / nsPerSec
}

// JSONSink writes one JSON object per detection plus a final summary.
type JSONSink struct {
	W io.Writer
}

func (j *JSONSink) Begin() error { return nil }

type jsonDetection struct {
	Type     string `json:"type"`
	Ts       uint64 `json:"ts"`
	Pid      uint32 `json:"pid"`
	Tid      uint32 `json:"tid"`
	Uid      uint32 `json:"uid"`
	Comm     string `json:"comm"`
	Syscall  string `json:"syscall"`
	Path     string `json:"path,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Port     uint32 `json:"port,omitempty"`
	Detector string `json:"detector"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

func (j *JSONSink) OnDetection(d Detection) error {
	rec := jsonDetection{
		Type:     "detection",
		Ts:       d.Event.Ts,
		Pid:      d.Event.Pid,
		Tid:      d.Event.Tid,
		Uid:      d.Event.Uid,
		Comm:     d.Event.Comm,
		Syscall:  d.Event.Syscall,
		Path:     d.Event.Path,
		Addr:     d.Event.Addr,
		Port:     d.Event.Port,
		Detector: d.Detector.ID,
		Category: d.Detector.Category,
		Severity: d.Detector.parsedSeverity.String(),
		Summary:  d.Detector.Summary,
	}
	b, err := json.Marshal(&rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = j.W.Write(b)
	return err
}

func (j *JSONSink) End(s AnalyzerStats) error {
	summary := struct {
		Type           string         `json:"type"`
		EventsRead     int            `json:"events_read"`
		EventsParsed   int            `json:"events_parsed"`
		EventsMatched  int            `json:"events_matched"`
		DetectionsHigh int            `json:"detections_high"`
		DetectionsMed  int            `json:"detections_med"`
		DetectionsLow  int            `json:"detections_low"`
		ByDetector     map[string]int `json:"by_detector"`
		ByCategory     map[string]int `json:"by_category"`
		FirstTs        uint64         `json:"first_ts"`
		LastTs         uint64         `json:"last_ts"`
	}{
		Type:           "summary",
		EventsRead:     s.EventsRead,
		EventsParsed:   s.EventsParsed,
		EventsMatched:  s.EventsMatched,
		DetectionsHigh: s.DetectionsHigh,
		DetectionsMed:  s.DetectionsMed,
		DetectionsLow:  s.DetectionsLow,
		ByDetector:     s.DetectorHits,
		ByCategory:     s.CategoryHits,
		FirstTs:        s.FirstTs,
		LastTs:         s.LastTs,
	}
	b, err := json.Marshal(&summary)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = j.W.Write(b)
	return err
}
