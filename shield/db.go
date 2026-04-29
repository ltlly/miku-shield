// Package shield implements miku-shield's anti-Frida detection layer
// on top of stackplz's syscall-tracing event stream.
//
// The package is pure Go (no eBPF) and processes JSON events emitted by
// stackplz. Loading the YAML detector library, classifying events, and
// rendering a timeline are split into separate files; this file owns
// the database (load + lookup).
package shield

import (
	"fmt"
	"io"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// Severity ranks how confidently a detector indicates an anti-Frida probe.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	}
	return "unknown"
}

// Label is the short uppercase form used in the pretty timeline.
func (s Severity) Label() string {
	switch s {
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MED "
	case SeverityLow:
		return "LOW "
	}
	return "??? "
}

// MatchSpec is the YAML representation of a detector's match block.
//
// Within a single MatchSpec, fields combine with implicit AND. Inside a
// list-typed field (Syscall, PathGlob, Port) the elements are OR'd.
type MatchSpec struct {
	Syscall   []string `yaml:"syscall"`
	PathExact string   `yaml:"path_exact"`
	PathGlob  yamlList `yaml:"path_glob"`
	Port      yamlUint `yaml:"port"`
	CommMatch yamlList `yaml:"comm_match"`
}

// yamlList allows YAML to provide either a single string or a list of
// strings; everything is normalised to []string at load time.
type yamlList []string

func (l *yamlList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*l = yamlList{node.Value}
		return nil
	}
	if node.Kind == yaml.SequenceNode {
		var v []string
		if err := node.Decode(&v); err != nil {
			return err
		}
		*l = v
		return nil
	}
	return fmt.Errorf("yaml list: unexpected node kind %d", node.Kind)
}

// yamlUint accepts either a single uint or a list of uints.
type yamlUint []uint32

func (u *yamlUint) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var v uint32
		if err := node.Decode(&v); err != nil {
			return err
		}
		*u = yamlUint{v}
		return nil
	}
	if node.Kind == yaml.SequenceNode {
		var v []uint32
		if err := node.Decode(&v); err != nil {
			return err
		}
		*u = v
		return nil
	}
	return fmt.Errorf("yaml uint: unexpected node kind %d", node.Kind)
}

// Detector is one entry in the YAML detector library.
type Detector struct {
	ID       string    `yaml:"id"`
	Severity string    `yaml:"severity"`
	Category string    `yaml:"category"`
	Summary  string    `yaml:"summary"`
	Match    MatchSpec `yaml:"match"`

	parsedSeverity Severity
}

// ParsedSeverity returns the Severity enum form (parsed at DB load time).
func (d *Detector) ParsedSeverity() Severity { return d.parsedSeverity }

// dbFile is the YAML root.
type dbFile struct {
	Version   int        `yaml:"version"`
	Detectors []Detector `yaml:"detectors"`
}

// Database is the runtime view of detectors.
type Database struct {
	Detectors []Detector

	// bySyscall is a fast index from syscall name → detectors that
	// list it in match.syscall. Detectors that omit match.syscall
	// (i.e. syscall-agnostic) end up under an empty-string key.
	bySyscall map[string][]int
}

// LoadDatabase reads and validates a YAML detector file.
func LoadDatabase(r io.Reader) (*Database, error) {
	dec := yaml.NewDecoder(r)
	var f dbFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}
	if f.Version == 0 {
		return nil, fmt.Errorf("missing version in detector yaml")
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported detector yaml version %d", f.Version)
	}
	db := &Database{
		Detectors: f.Detectors,
		bySyscall: map[string][]int{},
	}
	seen := map[string]bool{}
	for i := range db.Detectors {
		d := &db.Detectors[i]
		if d.ID == "" {
			return nil, fmt.Errorf("detector #%d: missing id", i)
		}
		if seen[d.ID] {
			return nil, fmt.Errorf("detector %q: duplicate id", d.ID)
		}
		seen[d.ID] = true
		switch d.Severity {
		case "high":
			d.parsedSeverity = SeverityHigh
		case "medium", "med":
			d.parsedSeverity = SeverityMedium
		case "low":
			d.parsedSeverity = SeverityLow
		default:
			return nil, fmt.Errorf("detector %s: bad severity %q", d.ID, d.Severity)
		}
		if len(d.Match.Syscall) == 0 {
			db.bySyscall[""] = append(db.bySyscall[""], i)
			continue
		}
		for _, sc := range d.Match.Syscall {
			db.bySyscall[sc] = append(db.bySyscall[sc], i)
		}
	}
	return db, nil
}

// LoadDatabaseFile is a convenience wrapper around LoadDatabase.
func LoadDatabaseFile(path string) (*Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadDatabase(f)
}

// detectorsFor returns the subset of detectors that *might* match for a
// given syscall. The general pool (those without match.syscall) is
// always appended.
func (db *Database) detectorsFor(syscall string) []*Detector {
	idx := append([]int{}, db.bySyscall[syscall]...)
	idx = append(idx, db.bySyscall[""]...)
	sort.Ints(idx)
	out := make([]*Detector, 0, len(idx))
	for _, i := range idx {
		out = append(out, &db.Detectors[i])
	}
	return out
}
