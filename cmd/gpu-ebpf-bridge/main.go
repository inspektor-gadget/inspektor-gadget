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

// Command gpu-ebpf-bridge polls GPU telemetry (NVML in v1) and
// publishes it through bpffs-pinned BPF maps. See README.md for the
// data flow and the API contract.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/maps"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/nvml"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/poller"
)

type options struct {
	mode              string
	pollInterval      time.Duration
	pinDir            string
	keepPins          bool
	logLevel          string
	showVersion       bool
	dump              bool
	hostPath          string
	symlinkNvidiaDevs bool
	idleIfNoGPU       bool
	nvmlLibraryPath   string
}

func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("gpu-ebpf-bridge", flag.ContinueOnError)
	var opt options
	fs.StringVar(&opt.mode, "mode", "auto",
		"Telemetry source: auto (try real, fall back to mock), real, mock")
	fs.DurationVar(&opt.pollInterval, "poll-interval", 100*time.Millisecond,
		"How often to poll the telemetry source")
	fs.StringVar(&opt.pinDir, "pin-dir", maps.DefaultPinDir,
		"bpffs directory under which to pin the maps")
	fs.BoolVar(&opt.keepPins, "keep-pins", false,
		"On clean shutdown, leave the pinned maps in place (default: unpin)")
	fs.StringVar(&opt.logLevel, "log-level", "info",
		"Logger level: debug, info, warn, error")
	fs.BoolVar(&opt.showVersion, "version", false, "Print version and exit")
	fs.BoolVar(&opt.dump, "dump", false,
		"Read the bpffs-pinned bridge maps and print their contents, then exit. "+
			"Useful as a bpftool-free debugging aid; does not start the poller.")
	fs.StringVar(&opt.hostPath, "host-path", "",
		"When set, the container is expected to bind-mount the host's "+
			"filesystem (or a subtree) at this path. Used together with "+
			"--symlink-nvidia-devs to reach the host's /dev/nvidia* and "+
			"with LD_LIBRARY_PATH to reach the host's libnvidia-ml.so.1. "+
			"Empty by default (standalone / non-containerized use).")
	fs.BoolVar(&opt.symlinkNvidiaDevs, "symlink-nvidia-devs", false,
		"On startup, glob ${host-path}/dev/nvidia* and create symlinks "+
			"in the container's /dev pointing at each entry. Required "+
			"when the container's own /dev has no NVIDIA nodes (typical "+
			"in kubernetes DaemonSet with host /dev bind-mounted at "+
			"/host/dev). No-op on hosts without an NVIDIA driver.")
	fs.BoolVar(&opt.idleIfNoGPU, "idle-if-no-gpu", false,
		"When NVML initialization fails with ErrNotAvailable, log a "+
			"warning and block until SIGTERM instead of exiting with an "+
			"error. Intended for helm-chart deployments on mixed clusters "+
			"where the same DaemonSet runs on GPU and non-GPU nodes; the "+
			"bridge simply idles on nodes without a driver.")
	fs.StringVar(&opt.nvmlLibraryPath, "nvml-library-path", "",
		"Absolute path to libnvidia-ml.so.1 to dlopen. Bypasses the "+
			"dynamic linker's default search so the bridge does not "+
			"need LD_LIBRARY_PATH pointing into the host's system "+
			"library directories (which can drag in mismatched host "+
			"libc / libpthread / libdl and trigger 'stack smashing "+
			"detected' when the container's glibc version differs). "+
			"If empty and --host-path is set, the bridge searches "+
			"${host-path}/usr/lib{,64,/x86_64-linux-gnu}/libnvidia-ml.so.1 "+
			"in order and uses the first match.")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	switch opt.mode {
	case "auto", "real", "mock":
	default:
		return options{}, fmt.Errorf("invalid --mode=%q (want: auto, real, mock)", opt.mode)
	}
	if opt.symlinkNvidiaDevs && opt.hostPath == "" {
		return options{}, fmt.Errorf("--symlink-nvidia-devs requires --host-path")
	}
	return opt, nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(unknown)"
}

// chooseSource resolves --mode to a concrete nvml.Poller. For "auto"
// it tries the real backend first and falls back to the mock if NVML
// is unavailable on this host (typical for non-GPU dev machines).
// libraryPath, if non-empty, is passed to the real backend so it
// dlopens libnvidia-ml.so.1 at that absolute path.
func chooseSource(ctx context.Context, mode, libraryPath string, logger *slog.Logger) (nvml.Poller, string, error) {
	tryReal := func() (nvml.Poller, error) {
		// SA4023: in the default (non-nvml) stub build newRealPoller always
		// returns a non-nil error, so staticcheck flags both the call (as
		// related information) and the comparison as statically "always true".
		// With -tags nvml the real backend can succeed and return nil, so this
		// is a false positive for the shipping build; suppress it on both lines.
		p, err := newRealPoller(libraryPath) //nolint:staticcheck
		if err != nil {                      //nolint:staticcheck
			return nil, err
		}
		if err := p.Init(ctx); err != nil {
			_ = p.Close()
			return nil, err
		}
		return p, nil
	}

	switch mode {
	case "real":
		p, err := tryReal()
		if err != nil {
			return nil, "", fmt.Errorf("real NVML backend requested but unavailable: %w", err)
		}
		return p, "real", nil
	case "mock":
		p := nvml.NewMock()
		if err := p.Init(ctx); err != nil {
			return nil, "", err
		}
		return p, "mock", nil
	case "auto":
		if p, err := tryReal(); err == nil {
			return p, "real", nil
		} else {
			logger.Info("NVML unavailable, falling back to mock backend", "err", err)
			p := nvml.NewMock()
			if err := p.Init(ctx); err != nil {
				return nil, "", err
			}
			return p, "mock", nil
		}
	default:
		return nil, "", fmt.Errorf("unhandled --mode=%q", mode)
	}
}

func run(args []string) error {
	opt, err := parseFlags(args)
	if err != nil {
		return err
	}
	if opt.showVersion {
		fmt.Printf("gpu-ebpf-bridge %s\n", version())
		return nil
	}
	if opt.dump {
		return runDump(opt.pinDir)
	}

	logger := newLogger(opt.logLevel)
	slog.SetDefault(logger)

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("RemoveMemlock: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if opt.symlinkNvidiaDevs {
		if err := linkNvidiaDevs(opt.hostPath, logger); err != nil {
			return fmt.Errorf("linking host nvidia devices: %w", err)
		}
	}

	libraryPath := opt.nvmlLibraryPath
	if libraryPath == "" && opt.hostPath != "" {
		libraryPath = findNvmlLibrary(opt.hostPath, logger)
	}

	source, sourceName, err := chooseSource(ctx, opt.mode, libraryPath, logger)
	if err != nil {
		if errors.Is(err, nvml.ErrNotAvailable) && opt.idleIfNoGPU {
			logger.Warn("NVML unavailable; entering idle mode until SIGTERM",
				"err", err,
				"hint", "install NVIDIA drivers, or run without --idle-if-no-gpu")
			<-ctx.Done()
			return nil
		}
		return err
	}

	bridge, err := maps.Open(opt.pinDir)
	if err != nil {
		_ = source.Close()
		return fmt.Errorf("opening bridge maps in %s: %w", opt.pinDir, err)
	}

	logger.Info("gpu-ebpf-bridge started",
		"version", version(),
		"source", sourceName,
		"pin-dir", opt.pinDir,
		"poll-interval", opt.pollInterval,
		"pid", os.Getpid())

	p, err := poller.New(poller.Config{
		PollInterval: opt.pollInterval,
		Source:       source,
		Bridge:       bridge,
		Logger:       logger,
	})
	if err != nil {
		_ = bridge.Close()
		_ = source.Close()
		return err
	}

	runErr := p.Run(ctx)

	// Clean shutdown path. Close releases FDs; Unpin removes bpffs
	// entries unless the operator asked us to keep them (e.g. they
	// want consumer gadgets to keep reading the last known values
	// across a bridge restart).
	logger.Info("shutting down")
	if cerr := bridge.Close(); cerr != nil {
		logger.Warn("bridge Close failed", "err", cerr)
	}
	if !opt.keepPins {
		if uerr := bridge.Unpin(); uerr != nil {
			logger.Warn("bridge Unpin failed", "err", uerr)
		} else {
			logger.Info("removed pinned maps", "pin-dir", opt.pinDir)
		}
	} else {
		logger.Info("leaving pinned maps in place (--keep-pins)", "pin-dir", opt.pinDir)
	}
	return runErr
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
