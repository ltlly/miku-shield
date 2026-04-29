package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/spf13/cobra"

	"github.com/ltlly/miku-shield/assets"
	"github.com/ltlly/miku-shield/shield"
	"github.com/ltlly/miku-shield/user/util"
)

var mitigateFlags struct {
	pkg         string
	uid         uint32
	duration    int
	detectorYAML string
	extraPaths   []string
	extraPorts   []uint16
	statInterval int
}

var mitigateExtraPortsRaw string

var mitigateCmd = &cobra.Command{
	Use:   "mitigate",
	Short: "load LSM-based file/socket-deny mitigation (Phase 2)",
	Long: `mitigate loads two LSM BPF programs that refuse open() of
known frida-server paths and connect() to known frida ports for the
target package's UID. Other apps and system services are unaffected.

The blocklist is built from the YAML detector library (only entries
whose match block has a path_glob without wildcards or a numeric port
are eligible — wildcards do not survive into the kernel-side hash map).

Example:

  miku-shield mitigate --pkg com.taobao.taobao --duration 300

  # add a custom path / port:
  miku-shield mitigate --pkg com.Qunar \
      --extra-path /data/local/tmp/my-frida \
      --extra-port 12345
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if mitigateFlags.uid == 0 && mitigateFlags.pkg == "" {
			return fmt.Errorf("--pkg or --uid is required")
		}
		uid := mitigateFlags.uid
		if uid == 0 {
			pis := util.Get_PackageInfos()
			ok, info := pis.FindPackageByName(mitigateFlags.pkg)
			if !ok {
				return fmt.Errorf("package %q not found on device", mitigateFlags.pkg)
			}
			uid = info.Uid
		}

		// Resolve detector YAML.
		yamlPath := mitigateFlags.detectorYAML
		if yamlPath == "" {
			exe, _ := os.Executable()
			yamlPath = filepath.Join(filepath.Dir(exe), "data", "known_detectors.yaml")
			if _, err := os.Stat(yamlPath); err != nil {
				yamlPath = "data/known_detectors.yaml"
			}
		}
		db, err := shield.LoadDatabaseFile(yamlPath)
		if err != nil {
			return fmt.Errorf("load detectors: %w", err)
		}

		paths, ports := shield.BlocklistFromDB(db)
		paths = append(paths, mitigateFlags.extraPaths...)
		extraPorts, err := parseUint16Slice(mitigateExtraPortsRaw)
		if err != nil {
			return fmt.Errorf("--extra-port: %w", err)
		}
		ports = append(ports, extraPorts...)
		if len(paths) == 0 && len(ports) == 0 {
			return fmt.Errorf("blocklist is empty — nothing to do")
		}

		// Load BPF object from embedded assets.
		objBytes, err := assets.Asset("user/assets/lsm_block.bpf.o")
		if err != nil {
			return fmt.Errorf("read embedded BPF object: %w", err)
		}
		var kernelBTF *btf.Spec
		if !util.SysfsBTFExists() {
			kernelBTF, _ = util.LoadFallbackKernelBTF()
		}

		l, err := shield.NewLoader(bytes.NewReader(objBytes), kernelBTF)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[miku-shield] mitigate uid=%d  paths=%d  ports=%d\n",
			uid, len(paths), len(ports))
		if err := l.Apply(shield.MitigationConfig{
			TargetUID:  uid,
			BlockPaths: paths,
			BlockPorts: ports,
		}); err != nil {
			return err
		}
		defer l.Close()

		// Print stats periodically until duration / signal.
		sigc := make(chan os.Signal, 2)
		signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(sigc)
		ticker := time.NewTicker(time.Duration(mitigateFlags.statInterval) * time.Second)
		defer ticker.Stop()
		deadline := time.NewTimer(time.Duration(mitigateFlags.duration) * time.Second)
		defer deadline.Stop()

		for {
			select {
			case <-ticker.C:
				if s, err := l.Stats(); err == nil {
					fmt.Fprintf(os.Stderr,
						"[stats] file_open: checked=%d blocked=%d  | sock_connect: checked=%d blocked=%d\n",
						s.FileOpenChecked, s.FileOpenBlocked,
						s.SockConnectChecked, s.SockConnectBlocked)
				}
			case <-sigc:
				return nil
			case <-deadline.C:
				return nil
			}
		}
	},
}

// parseUint16Slice parses comma-separated uint16 strings for the cobra
// flag (cobra has --uint16Slice but the helper is a bit nicer for our
// space-separated repeat-flag use case).
func parseUint16Slice(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	out := []uint16{}
	for _, part := range strings.Split(s, ",") {
		v, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
		if err != nil {
			return nil, err
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

func init() {
	mitigateCmd.Flags().StringVar(&mitigateFlags.pkg, "pkg", "", "Android package name (one of --pkg / --uid required)")
	mitigateCmd.Flags().Uint32Var(&mitigateFlags.uid, "uid", 0, "UID directly (skip package resolution)")
	mitigateCmd.Flags().IntVar(&mitigateFlags.duration, "duration", 300, "mitigation duration in seconds")
	mitigateCmd.Flags().StringVar(&mitigateFlags.detectorYAML, "detectors", "",
		"detector YAML file (default: <binary-dir>/data/known_detectors.yaml)")
	mitigateCmd.Flags().StringSliceVar(&mitigateFlags.extraPaths, "extra-path", nil,
		"add custom path to file_open blocklist (repeatable)")
	mitigateCmd.Flags().StringVar(&mitigateExtraPortsRaw, "extra-port", "",
		"comma-separated extra ports to add to socket_connect blocklist")
	mitigateCmd.Flags().IntVar(&mitigateFlags.statInterval, "stat-interval", 5,
		"seconds between stats prints to stderr")
	rootCmd.AddCommand(mitigateCmd)
}
