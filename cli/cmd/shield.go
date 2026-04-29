// miku-shield additions on top of stackplz.
//
// New cobra subcommands:
//
//	miku-shield analyze   — read stackplz JSON-Lines from stdin/file
//	                        and emit an anti-Frida detection timeline.
//	miku-shield identify  — spawn stackplz with the right flags for
//	                        anti-Frida observation, pipe the live JSON
//	                        stream through `analyze`.
//
// The actual matching logic lives in package shield/.
package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ltlly/miku-shield/shield"
)

// Default detector library lookup — relative to the binary path so the
// tool stays single-file deployable on /data/local/tmp.
const defaultDetectorRel = "data/known_detectors.yaml"

// shieldFlags are shared between identify and analyze.
type shieldFlags struct {
	detectorPath string
	output       string // "pretty" | "json"
	outFile      string
	minSeverity  string
}

func (sf *shieldFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&sf.detectorPath, "detectors", "",
		"path to detectors YAML (default: <binary-dir>/data/known_detectors.yaml)")
	cmd.Flags().StringVar(&sf.output, "output", "pretty", "output format: pretty | json")
	cmd.Flags().StringVarP(&sf.outFile, "out", "o", "", "write timeline to FILE (default stdout)")
	cmd.Flags().StringVar(&sf.minSeverity, "min-severity", "low",
		"drop detections below this level: low | medium | high")
}

func (sf *shieldFlags) loadDB() (*shield.Database, error) {
	path := sf.detectorPath
	if path == "" {
		exe, err := os.Executable()
		if err == nil {
			path = filepath.Join(filepath.Dir(exe), defaultDetectorRel)
		}
	}
	if path == "" {
		return nil, fmt.Errorf("detector library path not set and binary path unknown")
	}
	if _, err := os.Stat(path); err != nil {
		// Fall back to the source-tree-relative path so `go run` works
		// without a build step. This is best-effort.
		alt := filepath.Join("data", "known_detectors.yaml")
		if _, e2 := os.Stat(alt); e2 == nil {
			path = alt
		} else {
			return nil, fmt.Errorf("detectors yaml: %w", err)
		}
	}
	return shield.LoadDatabaseFile(path)
}

func (sf *shieldFlags) parseSeverity() (shield.Severity, error) {
	switch strings.ToLower(sf.minSeverity) {
	case "low", "":
		return shield.SeverityLow, nil
	case "med", "medium":
		return shield.SeverityMedium, nil
	case "high":
		return shield.SeverityHigh, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want low|medium|high)", sf.minSeverity)
}

func (sf *shieldFlags) makeSink(w io.Writer, header string) shield.Sink {
	if sf.output == "json" {
		return &shield.JSONSink{W: w}
	}
	return &shield.PrettySink{W: w, Header: header}
}

func (sf *shieldFlags) openOut() (io.Writer, func() error, error) {
	if sf.outFile == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.Create(sf.outFile)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

// ─────────── analyze (offline) ────────────────────────────────────────

var analyzeFlags shieldFlags

var analyzeCmd = &cobra.Command{
	Use:   "analyze [FILE]",
	Short: "post-process stackplz JSONL output, emit anti-Frida detection timeline",
	Long: `analyze reads a JSON-Lines event stream produced by
stackplz --json (e.g. captured into a file or piped over stdin) and
emits a timeline of anti-Frida detection attempts.

Pass FILE for a captured trace, or "-" / no argument for stdin:

  stackplz -j -n com.taobao.taobao --syscall openat,connect | \
    miku-shield analyze --output pretty

  miku-shield analyze --output json captured.jsonl > detections.jsonl
`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := analyzeFlags.loadDB()
		if err != nil {
			return err
		}
		minSev, err := analyzeFlags.parseSeverity()
		if err != nil {
			return err
		}
		var src io.Reader = os.Stdin
		header := "miku-shield analyze  src=stdin"
		if len(args) == 1 && args[0] != "-" {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			src = f
			header = "miku-shield analyze  src=" + args[0]
		}
		out, closeOut, err := analyzeFlags.openOut()
		if err != nil {
			return err
		}
		defer closeOut()

		a := &shield.Analyzer{
			DB:          db,
			Sink:        analyzeFlags.makeSink(out, header),
			MinSeverity: minSev,
		}
		return a.Run(src)
	},
}

// ─────────── identify (live) ──────────────────────────────────────────

var identifyFlags struct {
	shieldFlags
	pkg            string
	duration       int
	stackplzBin    string
	extraSyscalls  string
	stackplzVerbose bool
}

// defaultSyscalls are the syscalls Phase 1 needs to see in order to
// catch the anti-Frida fingerprints in known_detectors.yaml. Keep this
// list small — broader syscall sets blow up trace volume on real apps.
var defaultSyscalls = strings.Join([]string{
	"openat", "faccessat", "faccessat2",
	"newfstatat", "statx", "readlinkat",
	"connect",
}, ",")

var identifyCmd = &cobra.Command{
	Use:   "identify",
	Short: "live anti-Frida detection trace via embedded stackplz",
	Long: `identify spawns the bundled stackplz binary with a fixed set
of syscalls relevant to anti-Frida detection (openat, faccessat,
connect, readlinkat, statx, ...), pipes its JSON output through the
shield analyzer, and writes a timeline.

Example:

  miku-shield identify --pkg com.taobao.taobao --duration 60

The stackplz binary is looked up in this order:
  1. --stackplz-bin flag
  2. $MIKU_SHIELD_STACKPLZ env var
  3. <binary-dir>/stackplz
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if identifyFlags.pkg == "" {
			return fmt.Errorf("--pkg is required")
		}
		db, err := identifyFlags.loadDB()
		if err != nil {
			return err
		}
		minSev, err := identifyFlags.parseSeverity()
		if err != nil {
			return err
		}

		stackplzPath := identifyFlags.stackplzBin
		if stackplzPath == "" {
			stackplzPath = os.Getenv("MIKU_SHIELD_STACKPLZ")
		}
		if stackplzPath == "" {
			exe, _ := os.Executable()
			stackplzPath = filepath.Join(filepath.Dir(exe), "stackplz")
		}
		if _, err := os.Stat(stackplzPath); err != nil {
			return fmt.Errorf("stackplz binary not found at %s: %w", stackplzPath, err)
		}

		syscalls := defaultSyscalls
		if identifyFlags.extraSyscalls != "" {
			syscalls = syscalls + "," + identifyFlags.extraSyscalls
		}

		stackplzArgs := []string{
			"--btf",
			"-j",
			"-n", identifyFlags.pkg,
			"--syscall", syscalls,
		}

		ctxCmd := exec.Command(stackplzPath, stackplzArgs...)
		// Working directory matters: stackplz looks up its
		// config_syscall_aarch64.json relative to cwd.
		ctxCmd.Dir = filepath.Dir(stackplzPath)
		ctxCmd.Stderr = os.Stderr
		stdout, err := ctxCmd.StdoutPipe()
		if err != nil {
			return err
		}

		out, closeOut, err := identifyFlags.openOut()
		if err != nil {
			return err
		}
		defer closeOut()

		if err := ctxCmd.Start(); err != nil {
			return fmt.Errorf("start stackplz: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[miku-shield] stackplz pid=%d  pkg=%s  duration=%ds\n",
			ctxCmd.Process.Pid, identifyFlags.pkg, identifyFlags.duration)

		// Duration timer + Ctrl-C → forward SIGTERM to stackplz.
		done := make(chan struct{})
		sigc := make(chan os.Signal, 2)
		signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sigc)
		go func() {
			select {
			case <-time.After(time.Duration(identifyFlags.duration) * time.Second):
			case <-sigc:
			case <-done:
				return
			}
			_ = ctxCmd.Process.Signal(syscall.SIGTERM)
		}()

		header := fmt.Sprintf("miku-shield identify  pkg=%s  duration=%ds",
			identifyFlags.pkg, identifyFlags.duration)
		a := &shield.Analyzer{
			DB:          db,
			Sink:        identifyFlags.makeSink(out, header),
			MinSeverity: minSev,
		}
		runErr := a.Run(stdout)
		close(done)
		waitErr := ctxCmd.Wait()
		// SIGTERM exit is normal here.
		if runErr != nil {
			return runErr
		}
		if waitErr != nil {
			if ee, ok := waitErr.(*exec.ExitError); ok && ee.ProcessState.ExitCode() == -1 {
				return nil
			}
		}
		return nil
	},
}

func init() {
	analyzeFlags.bind(analyzeCmd)
	identifyFlags.bind(identifyCmd)
	identifyCmd.Flags().StringVar(&identifyFlags.pkg, "pkg", "", "Android package name (required)")
	identifyCmd.Flags().IntVar(&identifyFlags.duration, "duration", 60, "trace duration in seconds")
	identifyCmd.Flags().StringVar(&identifyFlags.stackplzBin, "stackplz-bin", "",
		"path to stackplz binary (default: <binary-dir>/stackplz)")
	identifyCmd.Flags().StringVar(&identifyFlags.extraSyscalls, "extra-syscalls", "",
		"extra syscall names to add on top of the Phase 1 default set")

	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(identifyCmd)
}
