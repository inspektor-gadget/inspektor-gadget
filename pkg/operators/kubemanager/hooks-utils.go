// Copyright 2025 The Inspektor Gadget authors
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

package kubemanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	nriv1 "github.com/containerd/nri/types/v1"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerhook "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	// Hook modes
	hookModeNone         = "none"
	hookModeAuto         = "auto"
	hookModeCrio         = "crio"
	hookModeNRI          = "nri"
	hookModePodInformer  = "podinformer"
	hookModeFanotifyEbpf = "fanotify+ebpf"
)

var crioRegex = regexp.MustCompile(`1:name=systemd:.*/crio-[0-9a-f]*\.scope`)

var supportedHookModes = []string{
	hookModeAuto,
	hookModeCrio,
	hookModeNRI,
	hookModePodInformer,
	hookModeFanotifyEbpf,
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

		path := filepath.Join("/opt/hooks/oci", file)
		destinationPath := filepath.Join(host.HostRoot, path)
		err := copyFile(destinationPath, path, 0o750)
		if err != nil {
			return fmt.Errorf("copying: %w", err)
		}
	}

	for _, file := range []string{"etc/containers/oci/hooks.d", "usr/share/containers/oci/hooks.d/"} {
		hookPath := filepath.Join(host.HostRoot, file)

		log.Infof("Installing OCI hooks configuration in %s", hookPath)
		err := os.MkdirAll(hookPath, 0o755)
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

func parseHookMode(hookMode string) (string, error) {
	path := "/proc/self/cgroup"
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	crio := false
	if crioRegex.Match(content) {
		log.Infof("CRI-O detected.")
		crio = true
	}

	if (hookMode == hookModeAuto) && crio {
		log.Info("Hook mode CRI-O detected")
		hookMode = hookModeCrio
	}

	switch hookMode {
	case hookModeCrio:
		err := installCRIOHooks()
		if err != nil {
			return "", fmt.Errorf("installing CRIO hooks: %w", err)
		}
	case hookModeNRI:
		err := installNRIHooks()
		if err != nil {
			return "", fmt.Errorf("installing NRI hooks: %w", err)
		}
	}

	parsedHookMode := hookModeAuto
	switch hookMode {
	case hookModeCrio, hookModeNRI:
		parsedHookMode = hookModeNone
	case hookModeFanotifyEbpf, hookModePodInformer:
		parsedHookMode = hookMode
	}

	log.Infof("Parsed hook mode: %s", parsedHookMode)

	return parsedHookMode, nil
}

func hookMode2ccOpts(node, hookMode string, fallbackPodInformer bool) ([]containercollection.ContainerCollectionOption, error) {
	var ccOpts []containercollection.ContainerCollectionOption

	podInformerUsed := false
	switch hookMode {
	case "none":
		// Used by nri and crio: They will call the hook-service directly to add and remove container
		log.Infof("KubeManager: hook mode: none")
		ccOpts = append(ccOpts, containercollection.WithInitialKubernetesContainers(node))
		ccOpts = append(ccOpts, containercollection.WithOCIConfigForInitialContainer())
	case "auto":
		if containerhook.Supported() {
			log.Infof("KubeManager: hook mode: fanotify+ebpf (auto)")
			ccOpts = append(ccOpts, containercollection.WithContainerFanotifyEbpf())
			ccOpts = append(ccOpts, containercollection.WithInitialKubernetesContainers(node))
			ccOpts = append(ccOpts, containercollection.WithOCIConfigForInitialContainer())
		} else {
			log.Infof("KubeManager: hook mode: podinformer (auto)")
			ccOpts = append(ccOpts, containercollection.WithPodInformer(node))
			podInformerUsed = true
		}
	case "podinformer":
		log.Infof("KubeManager: hook mode: podinformer")
		ccOpts = append(ccOpts, containercollection.WithPodInformer(node))
		podInformerUsed = true
	case "fanotify+ebpf":
		log.Infof("KubeManager: hook mode: fanotify+ebpf")
		ccOpts = append(ccOpts, containercollection.WithContainerFanotifyEbpf())
		ccOpts = append(ccOpts, containercollection.WithInitialKubernetesContainers(node))
		ccOpts = append(ccOpts, containercollection.WithOCIConfigForInitialContainer())
	default:
		return nil, fmt.Errorf("invalid hook mode: %s", hookMode)
	}

	if fallbackPodInformer && !podInformerUsed {
		log.Infof("KubeManager: enabling fallback podinformer")
		ccOpts = append(ccOpts, containercollection.WithFallbackPodInformer(node))
	}

	return ccOpts, nil
}
