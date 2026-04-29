package shield

import (
	"path"
	"regexp"
)

// Event is the analyzer's normalized view of a single syscall event
// from stackplz. It is decoupled from the stackplz JSON wire format so
// that callers can build events from any source (live trace, fixture
// jsonl, golden file).
type Event struct {
	// Boot-time monotonic timestamp in nanoseconds, copied straight
	// from stackplz's "boot_time" field. Used for ordering only — the
	// timeline renders relative seconds against the first event.
	Ts uint64

	Pid     uint32
	Tid     uint32
	Uid     uint32
	Comm    string
	Syscall string

	// Path / Port are the most-commonly-needed extracted args. The
	// extractor in pipeline.go fills these from the raw stackplz arg
	// list when available.
	Path string
	Port uint32
	Addr string

	// Raw is the original JSON line (for the --json output mode and
	// for debugging); empty when Event was built synthetically.
	Raw []byte
}

// Detection is a single (event × detector) match.
type Detection struct {
	Event    Event
	Detector *Detector
}

// Match returns every detector that fires on the given event.
//
// Implementation contract — kept simple on purpose:
//   - syscall must be one of detector.Match.Syscall (or that field empty)
//   - if path_glob present: at least one glob must match Event.Path
//   - if path_exact present: must equal Event.Path
//   - if port present: at least one port must equal Event.Port
//   - all stated conditions are AND'd
func (db *Database) Match(e Event) []Detection {
	if db == nil {
		return nil
	}
	out := make([]Detection, 0, 2)
	for _, d := range db.detectorsFor(e.Syscall) {
		if !matchOne(d, e) {
			continue
		}
		out = append(out, Detection{Event: e, Detector: d})
	}
	return out
}

func matchOne(d *Detector, e Event) bool {
	m := &d.Match

	// Path checks. If the detector specifies any path criterion the
	// event must carry a path *and* satisfy at least one.
	if m.PathExact != "" || len(m.PathGlob) > 0 {
		if e.Path == "" {
			return false
		}
		ok := false
		if m.PathExact != "" && m.PathExact == e.Path {
			ok = true
		}
		if !ok && len(m.PathGlob) > 0 {
			for _, g := range m.PathGlob {
				if globMatch(g, e.Path) {
					ok = true
					break
				}
			}
		}
		if !ok {
			return false
		}
	}

	// Port check.
	if len(m.Port) > 0 {
		ok := false
		for _, p := range m.Port {
			if uint32(p) == e.Port {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	// Comm regex check.
	if len(m.CommMatch) > 0 {
		if e.Comm == "" {
			return false
		}
		ok := false
		for _, expr := range m.CommMatch {
			re, err := regexp.Compile(expr)
			if err != nil {
				continue
			}
			if re.MatchString(e.Comm) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	return true
}

// globMatch matches a `**`-aware glob against an absolute path. We avoid
// pulling in a third-party doublestar lib by handling the common cases
// the detector library actually uses:
//
//	* matches one path segment, no /
//	** matches any number of path segments (>=0)
//
// All other characters are literal.
func globMatch(pattern, target string) bool {
	if pattern == target {
		return true
	}
	pp, tt := splitPath(pattern), splitPath(target)
	return globSegments(pp, tt)
}

func splitPath(p string) []string {
	// strings.Split keeps a leading empty for absolute paths;
	// path.Clean normalises duplicate slashes.
	p = path.Clean(p)
	out := make([]string, 0, 8)
	cur := ""
	for _, r := range p {
		if r == '/' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}

func globSegments(pp, tt []string) bool {
	if len(pp) == 0 {
		return len(tt) == 0
	}
	head, rest := pp[0], pp[1:]
	if head == "**" {
		// match zero or more target segments
		for i := 0; i <= len(tt); i++ {
			if globSegments(rest, tt[i:]) {
				return true
			}
		}
		return false
	}
	if len(tt) == 0 {
		return false
	}
	if !singleSegMatch(head, tt[0]) {
		return false
	}
	return globSegments(rest, tt[1:])
}

// singleSegMatch matches one path segment against one pattern segment
// where `*` means "any run of characters within this segment".
func singleSegMatch(pat, seg string) bool {
	// Fast path: no wildcard.
	if !containsByte(pat, '*') {
		return pat == seg
	}
	// Recursive descent — segments are short (<256 bytes) so this is
	// fine without compiling to a regex.
	if pat == "" {
		return seg == ""
	}
	if pat[0] == '*' {
		// match zero chars, or consume one char and retry.
		for i := 0; i <= len(seg); i++ {
			if singleSegMatch(pat[1:], seg[i:]) {
				return true
			}
		}
		return false
	}
	if seg == "" {
		return false
	}
	if pat[0] != seg[0] {
		return false
	}
	return singleSegMatch(pat[1:], seg[1:])
}

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}
