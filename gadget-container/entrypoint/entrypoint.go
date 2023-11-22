// Copyright 2019-2023 The Inspektor Gadget authors
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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	nriv1 "github.com/containerd/nri/types/v1"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"golang.org/x/sys/unix"
)

var crioRegex = regexp.MustCompile(`1:name=systemd:.*/crio-[0-9a-f]*\.scope`)

func getPrettyName() (string, error) {
	path := filepath.Join(host.HostRoot, "/etc/os-release")
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		if parts[0] == "PRETTY_NAME" {
			return strings.Trim(parts[1], "\""), nil
		}
	}

	err = scanner.Err()
	if err != nil {
		return "", fmt.Errorf("reading file %s: %w", path, err)
	}

	return "", fmt.Errorf("%s does not contain PRETTY_NAME", path)
}

func getKernelRelease() (string, error) {
	uts := &unix.Utsname{}
	if err := unix.Uname(uts); err != nil {
		return "", fmt.Errorf("calling uname: %w", err)
	}

	return unix.ByteSliceToString(uts.Release[:]), nil
}

func copyFile(destination, source string, filemode fs.FileMode) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("reading %s: %w", source, err)
	}

	info, err := os.Stat(destination)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat'ing %s: %w", destination, err)
	}

	if info != nil && info.IsDir() {
		destination = filepath.Join(destination, filepath.Base(source))
	}

	err = os.WriteFile(destination, content, filemode)
	if err != nil {
		return fmt.Errorf("writing %s: %w", destination, err)
	}

	return nil
}

func installCRIOHooks() error {
	log.Info("Installing hooks scripts on host...")

	path := filepath.Join(host.HostRoot, "opt/hooks/oci")
	err := os.MkdirAll(path, 0o755)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}

	for _, file := range []string{"ocihookgadget", "prestart.sh", "poststop.sh"} {
		log.Infof("Installing %s", file)

		srcPath := filepath.Join("/opt/hooks/oci", file)

		if strings.HasSuffix(file, ".sh") {
			// PoC
			confContent, err := os.ReadFile(srcPath)
			if err != nil {
				return fmt.Errorf("reading %q: %w", file, err)
			}
			socketArg := fmt.Sprintf(" /opt/hooks/oci/ocihookgadget -socketfile %s -hook ", fmt.Sprintf("/run/%s.gadgettracermanager.socket", os.Getenv("GADGET_NAMESPACE")))
			confContent = bytes.ReplaceAll(confContent, []byte(" /opt/hooks/oci/ocihookgadget -hook "), []byte(socketArg))
			confContent = bytes.ReplaceAll(confContent, []byte(" gadgettracermanager "), []byte(fmt.Sprintf(" gadgettracermanager-%s ", os.Getenv("GADGET_NAMESPACE"))))
			err = os.WriteFile(srcPath, confContent, 0o750)
			if err != nil {
				return fmt.Errorf("writing %s: %w", srcPath, err)
			}
			// -- end of PoC
		}

		destinationPath := filepath.Join(host.HostRoot, srcPath)
		err := copyFile(destinationPath, srcPath, 0o750)
		if err != nil {
			return fmt.Errorf("copying: %w", err)
		}
	}

	for _, file := range []string{"etc/containers/oci/hooks.d", "usr/share/containers/oci/hooks.d/"} {
		hookPath := filepath.Join(host.HostRoot, file)

		log.Infof("Installing OCI hooks configuration in %s", hookPath)
		os.MkdirAll(hookPath, 0o755)
		if err != nil {
			return fmt.Errorf("creating hook path %s: %w", path, err)
		}

		errCount := 0
		for _, config := range []string{"/opt/hooks/crio/gadget-prestart.json", "/opt/hooks/crio/gadget-poststop.json"} {
			err := copyFile(hookPath, config, 0o640)
			if err != nil {
				errCount++
			}
		}

		if errCount != 0 {
			log.Warn("Couldn't install OCI hooks configuration")
		} else {
			log.Info("Hooks installation done")
		}
	}

	return nil
}

func installNRIHooks() error {
	log.Info("Installing NRI hooks")

	destinationPath := filepath.Join(host.HostRoot, "opt/nri/bin")
	err := os.MkdirAll(destinationPath, 0o755)
	if err != nil {
		return fmt.Errorf("creating %s: %w", destinationPath, err)
	}

	err = copyFile(destinationPath, "/opt/hooks/nri/nrigadget", 0o640)
	if err != nil {
		return fmt.Errorf("copying: %w", err)
	}

	hostConfigPath := filepath.Join(host.HostRoot, "etc/nri/conf.json")

	// PoC
	confContent, err := os.ReadFile("/opt/hooks/nri/conf.json")
	if err != nil {
		return fmt.Errorf("reading /opt/hooks/nri/conf.json: %w", err)
	}
	confContent = bytes.ReplaceAll(confContent, []byte("/run/gadgettracermanager.socket"), []byte(fmt.Sprintf("/run/%s.gadgettracermanager.socket", os.Getenv("GADGET_NAMESPACE"))))
	err = os.WriteFile("/opt/hooks/nri/conf.json", confContent, 0o640)
	if err != nil {
		return fmt.Errorf("writing /opt/hooks/nri/conf.json: %w", err)
	}
	// -- end of PoC

	content, err := os.ReadFile(hostConfigPath)
	if err == nil {
		var configList nriv1.ConfigList

		err := json.Unmarshal(content, &configList)
		if err != nil {
			return fmt.Errorf("unmarshalling JSON %s: %w", hostConfigPath, err)
		}

		configList.Plugins = append(configList.Plugins, &nriv1.Plugin{Type: "nrigadget"})

		content, err = json.Marshal(configList)
		if err != nil {
			return fmt.Errorf("marshalling JSON: %w", err)
		}

		err = os.WriteFile(hostConfigPath, content, 0o640)
		if err != nil {
			return fmt.Errorf("writing %s: %w", hostConfigPath, err)
		}
	} else {
		destinationPath := filepath.Join(host.HostRoot, "etc/nri")
		err = os.MkdirAll(destinationPath, 0o755)
		if err != nil {
			return fmt.Errorf("creating %s: %w", destinationPath, err)
		}

		err := copyFile(destinationPath, "/opt/hooks/nri/conf.json", 0o640)
		if err != nil {
			return fmt.Errorf("copying: %w", err)
		}
	}

	return nil
}

func main() {
	if _, err := os.Stat(filepath.Join(host.HostRoot, "/bin")); os.IsNotExist(err) {
		log.Fatalf("%s must be executed in a pod with access to the host via %s", os.Args[0], host.HostRoot)
	}

	prettyName, err := getPrettyName()
	if err != nil {
		log.Warnf("os-release information not available. Some features could not work")
	}

	log.Infof("OS detected: %s", prettyName)

	kernelRelease, err := getKernelRelease()
	if err != nil {
		log.Fatalf("getting kernel release: %v", err)
	}

	log.Infof("Kernel detected: %s", kernelRelease)

	log.Infof("Gadget Image: %s", os.Getenv("GADGET_IMAGE"))

	log.Info("Deployment options:")
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "INSPEKTOR_GADGET_OPTION_") {
			log.Infof("%s", variable)
		}
	}

	log.Infof("Inspektor Gadget version: %s", os.Getenv("INSPEKTOR_GADGET_VERSION"))

	path := "/proc/self/cgroup"
	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("reading %s: %v", path, err)
	}

	crio := false
	if crioRegex.Match(content) {
		log.Infof("CRI-O detected.")
		crio = true
	}

	hookMode := os.Getenv("INSPEKTOR_GADGET_OPTION_HOOK_MODE")
	if (hookMode == "auto" || hookMode == "") && crio {
		log.Info("Hook mode CRI-O detected")
		hookMode = "crio"
	}

	switch hookMode {
	case "crio":
		err := installCRIOHooks()
		if err != nil {
			log.Fatalf("installing CRIO hooks: %v", err)
		}
	case "nri":
		err := installNRIHooks()
		if err != nil {
			log.Fatalf("installing NRI hooks: %v", err)
		}
	}

	gadgetTracerManagerHookMode := "auto"
	switch hookMode {
	case "crio", "nri":
		gadgetTracerManagerHookMode = "none"
	case "fanotify", "fanotify+ebpf", "podinformer":
		gadgetTracerManagerHookMode = hookMode
	}

	log.Infof("Gadget Tracer Manager hook mode: %s", gadgetTracerManagerHookMode)

	log.Info("Starting the Gadget Tracer Manager...")

	err = os.Chdir("/")
	if err != nil {
		log.Fatalf("changing directory: %v", err)
	}

	gadgetNamespace := os.Getenv("GADGET_NAMESPACE")

	instanceSocket := fmt.Sprintf("/run/%s.gadgettracermanager.socket", gadgetNamespace)
	for _, socket := range []string{"/run/gadgettracermanager.socket", "/run/gadgetservice.socket", instanceSocket} {
		os.Remove(socket)
	}

	os.Rename("/bin/gadgettracermanager", "/bin/gadgettracermanager-"+gadgetNamespace)

	args := []string{
		"gadgettracermanager-" + gadgetNamespace,
		"-serve",
		fmt.Sprintf("-hook-mode=%s", gadgetTracerManagerHookMode),
		"-controller",
		fmt.Sprintf("-fallback-podinformer=%s", os.Getenv("INSPEKTOR_GADGET_OPTION_FALLBACK_POD_INFORMER")),
		fmt.Sprintf("-socketfile=%s", instanceSocket),
	}

	err = syscall.Exec("/bin/gadgettracermanager-"+gadgetNamespace, args, os.Environ())
	if err != nil {
		log.Fatalf("exec'ing gadgettracermanager: %v", err)
	}

	log.Fatal("should never be printed...")
}
