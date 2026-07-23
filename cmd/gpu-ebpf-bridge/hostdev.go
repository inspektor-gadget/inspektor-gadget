// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// findNvmlLibrary searches for libnvidia-ml.so.1 under the host bind
// mount and returns its absolute path, or "" if not found. Ordered
// list of candidate directories covers the major Linux distros:
//
//	Debian / Ubuntu / AKS Ubuntu / GKE COS   → /usr/lib/x86_64-linux-gnu
//	RHEL / Fedora / CentOS / OpenShift       → /usr/lib64
//	minimal images / historic setups         → /usr/lib
//
// The bridge falls back to the dynamic linker's default search when
// this returns "", so hosts with unusual layouts (e.g. libnvidia-ml
// under /usr/lib/nvidia-575/) can still work via LD_LIBRARY_PATH or
// the explicit --nvml-library-path flag.
//
// Rationale for searching a specific path rather than relying on
// LD_LIBRARY_PATH: broad LD_LIBRARY_PATH values that include the
// host's system library dirs drag in the host's libc, libpthread,
// libdl, etc. When the container's glibc differs from the host's
// (e.g. distroless-debian12 container running on ubuntu-22.04 host),
// glibc's stack canaries mismatch and the process aborts with
// "*** stack smashing detected ***". Passing an absolute path via
// go-nvml's SetLibraryOptions avoids that entirely.
func findNvmlLibrary(hostPath string, logger *slog.Logger) string {
	candidates := []string{
		filepath.Join(hostPath, "usr", "lib", "x86_64-linux-gnu", "libnvidia-ml.so.1"),
		filepath.Join(hostPath, "usr", "lib64", "libnvidia-ml.so.1"),
		filepath.Join(hostPath, "usr", "lib", "libnvidia-ml.so.1"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			logger.Debug("found libnvidia-ml under host-path", "path", c)
			return c
		}
	}
	logger.Debug("libnvidia-ml not found under host-path; falling back to dlopen default",
		"host-path", hostPath, "searched", candidates)
	return ""
}

// hostPath/dev/nvidia*, so that NVML and the CUDA driver find the
// devices at the paths they expect ("/dev/nvidiactl", "/dev/nvidia0",
// ...) even when the container image itself carries no /dev entries
// and the container's own /dev is a fresh tmpfs.
//
// This is intended for the helm-chart deployment where /host/dev is
// bind-mounted from the node's /dev. It is a no-op on any host that
// has no NVIDIA driver: the glob simply returns no entries and NVML
// initialisation fails on the next step, which the bridge's
// --idle-if-no-gpu flag can then catch.
//
// Existing symlinks at the destination are replaced. Regular files or
// directories at the destination are left alone (safer default; the
// operator can remove them manually if they conflict).
//
// Nested directories under /host/dev/nvidia* (notably nvidia-caps/
// used for MIG) are not linked recursively in v1 because we do not
// yet support MIG telemetry; add when MIG support lands.
func linkNvidiaDevs(hostPath string, logger *slog.Logger) error {
	if hostPath == "" {
		return fmt.Errorf("--symlink-nvidia-devs requires --host-path to be set")
	}
	hostDev := filepath.Join(hostPath, "dev")
	entries, err := filepath.Glob(filepath.Join(hostDev, "nvidia*"))
	if err != nil {
		return fmt.Errorf("glob %s/nvidia*: %w", hostDev, err)
	}
	if len(entries) == 0 {
		logger.Info("no /dev/nvidia* entries found on host; skipping symlinks",
			"host-dev", hostDev)
		return nil
	}
	for _, src := range entries {
		info, err := os.Lstat(src)
		if err != nil {
			logger.Warn("stat failed for host nvidia entry",
				"path", src, "err", err)
			continue
		}
		if info.IsDir() {
			// e.g. /dev/nvidia-caps (MIG). Skipped in v1; see
			// function docstring.
			logger.Debug("skipping directory (not linked in v1)", "path", src)
			continue
		}
		dst := filepath.Join("/dev", filepath.Base(src))
		if existing, err := os.Lstat(dst); err == nil {
			// Already there. Three cases:
			//   1. character device: the container runtime (typically
			//      containerd for privileged containers) already
			//      bind-mounted the host device at this path. Nothing
			//      to do; the bridge can open it directly.
			//   2. symlink: from a previous bridge run (idempotent
			//      restart). Refresh it to point at the current
			//      host-path in case host-path changed.
			//   3. anything else (regular file, dir): refuse to
			//      replace; something is unexpected on this node.
			if existing.Mode()&os.ModeCharDevice != 0 {
				logger.Debug("device already present in container /dev; skipping symlink",
					"dst", dst)
				continue
			}
			if existing.Mode()&os.ModeSymlink == 0 {
				logger.Warn("refusing to replace non-symlink non-device at destination",
					"dst", dst, "mode", existing.Mode())
				continue
			}
			if err := os.Remove(dst); err != nil {
				logger.Warn("failed to remove existing symlink",
					"dst", dst, "err", err)
				continue
			}
		}
		if err := os.Symlink(src, dst); err != nil {
			logger.Warn("symlink creation failed",
				"container", dst, "host", src, "err", err)
			continue
		}
		logger.Debug("linked nvidia device", "container", dst, "host", src)
	}
	return nil
}
