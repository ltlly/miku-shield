package util

import (
	"os"

	"github.com/cilium/ebpf/btf"
)

// FallbackBTFPaths is the ordered list of file system paths miku-shield
// will try if the running kernel does not expose its BTF at the standard
// /sys/kernel/btf/vmlinux location.
//
// /mnt/vendor/persist/vmlinux.btf is the install path used by the
// alioth-kernel-research 4.19 backport (see kernel_research's
// install-btf-to-persist.sh) — that kernel ships the BTF firmware loader
// patch but does not always expose the BTF in sysfs.
var FallbackBTFPaths = []string{
	"/mnt/vendor/persist/vmlinux.btf",
}

// LoadFallbackKernelBTF returns a *btf.Spec from the first fallback path
// that exists, or (nil, nil) if none do. It does NOT consult
// /sys/kernel/btf/vmlinux — the cilium/ebpf default loader already
// handles that path; this helper is invoked only after the default
// loader has failed (or proactively for known-broken kernels).
func LoadFallbackKernelBTF() (*btf.Spec, error) {
	for _, p := range FallbackBTFPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		spec, err := btf.LoadSpec(p)
		if err != nil {
			return nil, err
		}
		return spec, nil
	}
	return nil, nil
}

// SysfsBTFExists reports whether /sys/kernel/btf/vmlinux is present.
// libbpf and cilium/ebpf both look there first; if it is missing we
// must supply a Spec ourselves via VerifierOptions.KernelTypes.
func SysfsBTFExists() bool {
	_, err := os.Stat(SYS_KERNEL_BTF_VMLINUX)
	return err == nil
}
