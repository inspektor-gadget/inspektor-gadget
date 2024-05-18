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
	"os/exec"
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

const (
	wslExePath = "/mnt/c/WINDOWS/system32/wsl.exe"
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
		return errors.New("need CAP_SYS_ADMIN (please try --auto-sd-unit-restart)")
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
func autoMountFilesystems(dryRun bool) ([]string, error) {
	var mountsSuggested []string

	fs := []struct {
		name    string
		paths   []string
		magic   int64
		suggest bool // suggest mounting this filesystem
	}{
		{
			"bpf",
			[]string{"/sys/fs/bpf"},
			unix.BPF_FS_MAGIC,
			false, // do not make 'ig --auto-mount-filesystems=false' fail if bpffs is not mounted
		},
		{
			"debugfs",
			[]string{"/sys/kernel/debug"},
			unix.DEBUGFS_MAGIC,
			true,
		},
		{
			"tracefs",
			[]string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"},
			unix.TRACEFS_MAGIC,
			true,
		},
	}

filesystemLoop:
	for _, f := range fs {
		var statfs unix.Statfs_t
		for _, path := range f.paths {
			if err := unix.Statfs(path, &statfs); err != nil {
				log.Debugf("statfs returned error on %s: %s", path, err)
				continue
			}
			if statfs.Type == f.magic {
				log.Debugf("%s already mounted", f.name)
				continue filesystemLoop
			}
		}

		if f.suggest {
			mountsSuggested = append(mountsSuggested, f.name)
		}
		if dryRun {
			continue
		}

		if err := unix.Mount("none", f.paths[0], f.name, 0, ""); err != nil {
			return mountsSuggested, fmt.Errorf("mounting %s: %w", f.paths[0], err)
		}
		log.Debugf("%s mounted (%s)", f.name, f.paths[0])
	}
	return mountsSuggested, nil
}

// isDockerWithWSLIntegration returns true if the process is running in a WSL
// distribution with docker configured to use the WSL2 integration.
func isDockerDesktopWSL2() bool {
	dockerExePath, _ := exec.LookPath("docker")
	if dockerExePath != "" {
		dockerLinkPath, _ := os.Readlink(dockerExePath)
		if strings.HasPrefix(dockerLinkPath, "/mnt/wsl/docker-desktop/cli-tools/") {
			return true
		}
	}
	return false
}

func isPodmanDesktopWSL2() bool {
	podmanExePath, _ := exec.LookPath("podman")
	if podmanExePath != "" {
		if _, err := os.Stat("/mnt/wsl/podman-sockets/podman-machine-default/podman-root.sock"); err == nil {
			return true
		}
	}
	return false
}

// isKernelWSL2 returns true if the kernel is WSL2.
func isKernelWSL2() bool {
	var utsname unix.Utsname
	err := unix.Uname(&utsname)
	if err != nil {
		return false
	}
	release := unix.ByteSliceToString(utsname.Release[:])
	return strings.HasSuffix(release, "-WSL2")
}

// getPid1Environ returns the environment variables of the init process in the
// given procfs path.
func getPid1Environ(procPath string) map[string]string {
	environBytes, _ := os.ReadFile(filepath.Join(procPath, "1", "environ"))
	environLines := strings.Split(string(environBytes), "\000")
	environ := make(map[string]string)
	for _, line := range environLines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			environ[parts[0]] = parts[1]
		}
	}
	return environ
}

// getWSLDistroName returns the WSL distribution name from the environment
func getWSLDistroName() string {
	// When running ig in a container started with "-v /:/host --pid=host":
	// - /proc refers to the docker-desktop pidns because the container
	//   inherits the pidns from runc.
	// - /host/proc refers to the WSL distribution where the Docker client was
	//   executed because the volume host path is translated automatically from
	//   the docker client context to the docker server context.
	// Therefore, use "/proc" to know if the docker server us running in a
	// separate WSL machine.
	pid1Environ := getPid1Environ("/proc")

	// WSL machine's pid1 uses $WSL2_DISTRO_NAME, but child processes use
	// $WSL_DISTRO_NAME, including the child pidns where runc is running (the
	// only one we have access to with --pid=host). Since we don't know at this
	// point if we're running directly in a WSL machine or in container runtime
	// pidns, we need to test both variables.
	wslDistroName := pid1Environ["WSL2_DISTRO_NAME"]
	if wslDistroName == "" {
		wslDistroName = pid1Environ["WSL_DISTRO_NAME"]
	}

	log.Debugf("WSL distribution: %s", wslDistroName)
	return wslDistroName
}

func suggestWSLWorkaround() error {
	if !isKernelWSL2() {
		return nil
	}

	wslDistroName := getWSLDistroName()

	target, err := os.Readlink(HostProcFs + "/self")
	hostProcFsAvailable := target != "" && err == nil

	log.Debugf("$HOST_ROOT: %s", HostRoot)
	log.Debugf("Host procfs available: %v", hostProcFsAvailable)

	// pid 1 (/init) should have $WSL2_DISTRO_NAME defined. If it's not defined,
	// we're likely running in a container with its own pid namespace.
	// If the host proc fs is available, this is probably Docker installed on
	// the WSL distribution (not Docker Desktop with WSL integration).
	if wslDistroName == "" && !hostProcFsAvailable {
		return fmt.Errorf("detecting WSL distribution name: empty name (please try to run docker with --pid=host)")
	}

	if !hostProcFsAvailable {
		return fmt.Errorf("host procfs not available (please try to run ig with --auto-wsl-workaround)")
	}

	if isDockerDesktopWSL2() || isPodmanDesktopWSL2() {
		if _, err := os.Stat(filepath.Join(HostRoot, wslExePath)); err != nil {
			log.Warnf("Docker or Podman uses WSL integration but cannot use wsl.exe workaround")
			return nil
		}

		// We can use the workaround based on wsl.exe
		return fmt.Errorf("docker or podman with WSL integration detected  (please try to run ig with --auto-wsl-workaround)")
	}
	return nil
}

func findProcessInProcfs(procPath string, cmd string) (int, error) {
	processes, err := os.ReadDir(procPath)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", procPath, err)
	}
	for _, p := range processes {
		if !p.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}

		cmdlineBytes, _ := os.ReadFile(filepath.Join(procPath, p.Name(), "cmdline"))
		currentCmdLine := strings.Split(string(cmdlineBytes), "\x00")
		if currentCmdLine[0] != cmd {
			continue
		}

		log.Debugf("Found process %q: pid %s", cmd, p.Name())
		return pid, nil
	}
	return 0, fmt.Errorf("process not found: %q", cmd)
}

// autoWSLWorkaround overrides HostRoot and HostProcFs if necessary.
// There are different scenarios to support:
//
//  1. ig running in a WSL distribution (not in a container)
//     - Docker running natively in the WSL distribution
//     => nothing to do, it's like on native Linux machines
//     - Docker running with the WSL2 integration
//     => use wsl.exe to find the container runtime procfs
//
//  2. ig running in a native container (not in a container running in WSL)
//     => nothing to do, it's like on native Linux machines
//
//  3. ig running in a container from Docker Desktop with WSL2 integration
//     => requires --pid=host and procfs substituting because -v /:/host does
//     not give access to the container runtime filesystem.
//
// Same scenarios with Podman.
func autoWSLWorkaround() error {
	if !isKernelWSL2() {
		return nil
	}

	wslDistroName := getWSLDistroName()

	inContainerDistro := wslDistroName == "docker-desktop" || wslDistroName == "podman-machine-default"
	target, err := os.Readlink(HostProcFs + "/self")
	hostProcFsAvailable := target != "" && err == nil

	log.Debugf("$HOST_ROOT: %s", HostRoot)
	log.Debugf("Host procfs available: %v", hostProcFsAvailable)

	if inContainerDistro && !hostProcFsAvailable {
		log.Debugf("Using WSL workaround for running in %q", wslDistroName)

		// Use /proc and not /host/proc to select the pidns of the container runtime
		procfsFromDockerDesktop := "/proc"

		// Find lifecycle-server process and set HOST_PID to its root
		pid, err := findProcessInProcfs(procfsFromDockerDesktop, "/usr/bin/lifecycle-server")
		if err != nil {
			return err
		}

		HostRoot = fmt.Sprintf("/proc/%d/root/", pid)
		HostProcFs = filepath.Join(HostRoot, "/proc")
		log.Debugf("Overriding HostRoot=%s HostProcFs=%s (lifecycle-server)", HostRoot, HostProcFs)
		return nil
	}

	if isDockerDesktopWSL2() {
		log.Debugf("Using WSL workaround for using Docker Desktop with WSL integration")

		procfsFromDockerDesktop := filepath.Join(HostRoot, "/mnt/wsl/docker-desktop-procfs")
		procfsInDockerDesktop := "/mnt/host/wsl/docker-desktop-procfs"
		// Bind mount procfs from the docker-desktop machine if not already done
		_, err := os.Stat(filepath.Join(procfsFromDockerDesktop, "1"))
		if err != nil {
			log.Debugf("Mounting procfs from docker-desktop machine to %s", procfsFromDockerDesktop)

			os.MkdirAll(procfsFromDockerDesktop, 0o500)
			cmd := exec.Command(filepath.Join(HostRoot, wslExePath),
				"-d", "docker-desktop",
				"--cd", "/",
				"-u", "root",
				"mount", "--bind", "/proc", procfsInDockerDesktop)
			stdoutStderr, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("running wsl.exe: %w\n%s", err, stdoutStderr)
			}
		} else {
			log.Debugf("procfs from docker-desktop machine already available at %s", procfsFromDockerDesktop)
		}
		targetProcess := "/usr/bin/lifecycle-server"
		pid, err := findProcessInProcfs(procfsFromDockerDesktop, targetProcess)
		if err != nil {
			return err
		}
		HostRoot = filepath.Join(procfsFromDockerDesktop, fmt.Sprint(pid), "root")
		HostProcFs = filepath.Join(HostRoot, "/proc")
		log.Debugf("Overriding HostRoot=%s HostProcFs=%s (%s)", HostRoot, HostProcFs, targetProcess)
		return nil
	}

	if isPodmanDesktopWSL2() {
		log.Debugf("Using WSL workaround for using Podman Desktop with WSL integration")

		procfsFromPodmanDesktop := filepath.Join(HostRoot, "/mnt/wsl/podman-desktop-procfs")
		procfsInPodmanDesktop := "/mnt/wsl/podman-desktop-procfs"
		// Bind mount procfs from the podman-desktop machine if not already done
		_, err := os.Stat(filepath.Join(procfsFromPodmanDesktop, "1"))
		if err != nil {
			log.Debugf("Mounting procfs from podman-desktop machine to %s", procfsFromPodmanDesktop)

			os.MkdirAll(procfsFromPodmanDesktop, 0o500)
			cmd := exec.Command(filepath.Join(HostRoot, wslExePath),
				"-d", "podman-machine-default",
				"--cd", "/",
				"-u", "root",
				"mount", "--bind", "/proc", procfsInPodmanDesktop)
			stdoutStderr, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("running wsl.exe: %w\n%s", err, stdoutStderr)
			}
		} else {
			log.Debugf("procfs from podman-desktop machine already available at %s", procfsFromPodmanDesktop)
		}
		targetProcess := "/lib/systemd/systemd"
		pid, err := findProcessInProcfs(procfsFromPodmanDesktop, targetProcess)
		if err != nil {
			return err
		}
		HostRoot = filepath.Join(procfsFromPodmanDesktop, fmt.Sprint(pid), "root")
		HostProcFs = filepath.Join(HostRoot, "/proc")
		log.Debugf("Overriding HostRoot=%s HostProcFs=%s (%s)", HostRoot, HostProcFs, targetProcess)
		return nil
	}

	log.Debugf("No WSL workaround used")
	return nil
}
