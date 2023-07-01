//go:build linux
// +build linux

// Copyright 2023 The Inspektor Gadget authors
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

// Package host provides ways to access the host filesystem.
//
// Inspektor Gadget can run either in the host or in a container. When running
// in a container, the host filesystem must be available in a specific
// directory.
package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func hasCapSysAdmin() (bool, error) {
	c, err := capability.NewPid2(0)
	if err != nil {
		return false, err
	}
	err = c.Load()
	if err != nil {
		return false, err
	}
	return c.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN), nil
}

func suggestSdUnitRestart() error {
	_, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if errors.Is(err, os.ErrNotExist) {
		// Not running in a pod. Not suggesting --auto-sd-unit-restart
		return nil
	}

	hasCap, err := hasCapSysAdmin()
	if err != nil {
		return err
	}
	if !hasCap {
		return errors.New("need CAP_SYS_ADMIN (did you try --auto-sd-unit-restart?)")
	}
	return nil
}

// autoSdUnitRestart will automatically restart the process in a privileged
// systemd unit if the current process does not have enough capabilities.
func autoSdUnitRestart() (exit bool, err error) {
	const IgInSystemdUnitEnv = "IG_IN_SYSTEMD_UNIT"

	// No recursive restarts
	if os.Getenv(IgInSystemdUnitEnv) == "1" {
		return false, nil
	}

	// If we already have CAP_SYS_ADMIN, we don't need a workaround
	hasCap, err := hasCapSysAdmin()
	if err != nil {
		return false, err
	}
	if hasCap {
		return false, nil
	}

	// From here, we decided to use the workaround. This function will return
	// exit=true.

	if HostRoot == "/" {
		return true, errors.New("host rootfs not found")
	}

	// if the host does not use systemd, we cannot use this workaround
	_, err = os.Stat(filepath.Join(HostRoot, "/run/systemd/private"))
	if err != nil {
		return true, errors.New("systemd private socket not found")
	}

	// Only root can talk to the systemd socket
	if os.Geteuid() != 0 {
		return true, errors.New("need root user")
	}

	runID := uuid.New().String()[:8]
	unitName := fmt.Sprintf("kubectl-debug-ig-%s.service", runID)
	log.Debugf("Missing capability. Starting systemd unit %q", unitName)

	// systemdDbus.NewSystemdConnectionContext() hard codes the path to the
	// systemd socket to /run/systemd/private. We need to make sure that this
	// path exists (if the /run:/run mount was set up correctly). If it doesn't
	// exist, we create the symlink to /host/run/systemd/private.
	_, err = os.Stat("/run/systemd/private")
	if errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll("/run/systemd", 0o755)
		if err != nil {
			return true, err
		}

		err = os.Symlink("/host/run/systemd/private", "/run/systemd/private")
		if err != nil {
			return true, fmt.Errorf("linking /run/systemd/private: %w", err)
		}
	} else if err != nil {
		return true, fmt.Errorf("statting /run/systemd/private: %w", err)
	}

	conn, err := systemdDbus.NewSystemdConnectionContext(context.TODO())
	if err != nil {
		return true, fmt.Errorf("connecting to systemd: %w", err)
	}
	defer conn.Close()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	statusChan := make(chan string, 1)
	cmd := []string{
		fmt.Sprintf("/proc/%d/root/usr/bin/ig", os.Getpid()),
	}
	cmd = append(cmd, os.Args[1:]...)
	envs := []string{IgInSystemdUnitEnv + "=1"}
	isTerminal := term.IsTerminal(int(os.Stdin.Fd())) || term.IsTerminal(int(os.Stdout.Fd())) || term.IsTerminal(int(os.Stderr.Fd()))
	if isTerminal && os.Getenv("TERM") != "" {
		envs = append(envs, "TERM="+os.Getenv("TERM"))
	}

	properties := []systemdDbus.Property{
		systemdDbus.PropDescription("Inspektor Gadget via kubectl debug"),
		// Type=oneshot ensures that StartTransientUnitContext will only return "done" when the job is done
		systemdDbus.PropType("oneshot"),
		// Pass stdio to the systemd unit
		{
			Name:  "StandardInputFileDescriptor",
			Value: dbus.MakeVariant(dbus.UnixFD(unix.Stdin)),
		},
		{
			Name:  "StandardOutputFileDescriptor",
			Value: dbus.MakeVariant(dbus.UnixFD(unix.Stdout)),
		},
		{
			Name:  "StandardErrorFileDescriptor",
			Value: dbus.MakeVariant(dbus.UnixFD(unix.Stderr)),
		},
		{
			Name:  "Environment",
			Value: dbus.MakeVariant(envs),
		},
		systemdDbus.PropExecStart(cmd, true),
	}

	_, err = conn.StartTransientUnitContext(context.TODO(),
		unitName, "fail", properties, statusChan)
	if err != nil {
		return true, fmt.Errorf("starting transient unit %q: %w", unitName, err)
	}

	select {
	case s := <-statusChan:
		log.Debugf("systemd unit %q returned %q", unitName, s)
		// "done" indicates successful execution of a job
		// See https://pkg.go.dev/github.com/coreos/go-systemd/v22/dbus#Conn.StartUnit
		if s != "done" {
			conn.ResetFailedUnitContext(context.TODO(), unitName)

			return true, fmt.Errorf("creating systemd unit `%s`: got `%s`", unitName, s)
		}
	case sig := <-signalChan:
		log.Debugf("%s: interrupt systemd unit %q", sig, unitName)
		statusStopChan := make(chan string, 1)
		_, err := conn.StopUnitContext(context.TODO(), unitName, "replace", statusStopChan)
		if err != nil {
			return true, fmt.Errorf("stopping transient unit %q: %w", unitName, err)
		}
		s := <-statusChan
		if s != "done" && s != "canceled" {
			return true, fmt.Errorf("stopping transient unit %q: got `%s`", unitName, s)
		}
	}

	return true, nil
}

// autoMount ensures that filesystems are mounted correctly.
// Some environments (e.g. minikube) runs with a read-only /sys without bpf
// https://github.com/kubernetes/minikube/blob/99a0c91459f17ad8c83c80fc37a9ded41e34370c/deploy/kicbase/entrypoint#L76-L81
// Docker Desktop with WSL2 also has filesystems unmounted.
//
// If dryRun is true, autoMount will only check if the filesystems need to be
// mounted.
// Returns the list of filesystems that need to be mounted.
func autoMountFilesystems(dryRun bool) (mountsSuggested []string, err error) {
	fs := []struct {
		name    string
		path    string
		magic   int64
		suggest bool // suggest mounting this filesystem
	}{
		{
			"bpf",
			"/sys/fs/bpf",
			unix.BPF_FS_MAGIC,
			false, // do not make 'ig --auto-mount-filesystems=false' fail if bpffs is not mounted
		},
		{
			"debugfs",
			"/sys/kernel/debug",
			unix.DEBUGFS_MAGIC,
			true,
		},
		{
			"tracefs",
			"/sys/kernel/tracing",
			unix.TRACEFS_MAGIC,
			true,
		},
	}
	for _, f := range fs {
		var statfs unix.Statfs_t
		err = unix.Statfs(f.path, &statfs)
		if err != nil {
			return mountsSuggested, fmt.Errorf("statfs %s: %w", f.path, err)
		}
		if statfs.Type == f.magic {
			log.Debugf("%s already mounted", f.name)
			continue
		}
		if f.suggest {
			mountsSuggested = append(mountsSuggested, f.name)
		}
		if dryRun {
			continue
		}

		err = unix.Mount("none", f.path, f.name, 0, "")
		if err != nil {
			return mountsSuggested, fmt.Errorf("mounting %s: %w", f.path, err)
		}
		log.Debugf("%s mounted (%s)", f.name, f.path)
	}
	return
}

func suggestWSLWorkaround() error {
	var utsname unix.Utsname
	err := unix.Uname(&utsname)
	if err != nil {
		return err
	}
	release := unix.ByteSliceToString(utsname.Release[:])
	if !strings.HasSuffix(release, "-WSL2") {
		return nil
	}

	// If /host/proc is correctly set up, we don't need this workaround
	target, err := os.Readlink(HostProcFs + "/self")
	if target != "" && err == nil {
		return nil
	}

	return fmt.Errorf("%s/self not found on WSL2 (did you try --auto-wsl-workaround?)", HostProcFs)
}

// autoWSLWorkaround overrides HostRoot and HostProcFs if necessary.
// Docker Desktop with WSL2 sets up host volumes with weird pidns.
func autoWSLWorkaround() error {
	// If we're not in a container, we can't use this workaround
	if HostRoot == "/" {
		return nil
	}

	// If /host/proc is correctly set up, we don't need this workaround
	target, err := os.Readlink(HostProcFs + "/self")
	if target != "" && err == nil {
		return nil
	}

	log.Warnf("%s's pidns is neither the current pidns or a parent of the current pidns. Remounting.", HostProcFs)
	err = unix.Mount("/proc", HostProcFs, "", unix.MS_BIND, "")
	if err != nil {
		return fmt.Errorf("remounting %s: %w", HostProcFs, err)
	}
	// Find lifecycle-server process and set HOST_PID to its root
	processes, err := os.ReadDir(HostProcFs)
	if err != nil {
		return fmt.Errorf("reading %s: %w", HostProcFs, err)
	}
	for _, p := range processes {
		if !p.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}

		cmdLine := GetProcCmdline(pid)
		if cmdLine[0] != "/usr/bin/lifecycle-server" {
			continue
		}
		log.Debugf("Found lifecycle-server process %s", p.Name())

		buf, err := os.ReadFile(fmt.Sprintf("/proc/%s/cgroup", p.Name()))
		if err != nil {
			continue
		}
		if !strings.Contains(string(buf), "/podruntime/docker") {
			continue
		}
		log.Debugf("Found lifecycle-server process %s in cgroup /podruntime/docker", p.Name())

		HostRoot = fmt.Sprintf("/proc/%s/root/", p.Name())
		HostProcFs = filepath.Join(HostRoot, "/proc")
		log.Warnf("Overriding HostRoot=%s HostProcFs=%s (lifecycle-server)", HostRoot, HostProcFs)

		return nil
	}

	return errors.New("lifecycle-server process not found")
}
