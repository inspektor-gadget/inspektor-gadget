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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

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

func parseHookMode(hookMode string) (string, error) {
	if hookMode == hookModeCrio {
		err := installCRIOHooks()
		if err != nil {
			return "", fmt.Errorf("installing CRIO hooks: %w", err)
		}
	}

	parsedHookMode := hookModeAuto
	switch hookMode {
	case hookModeCrio:
		parsedHookMode = hookModeNone
	case hookModeNRI, hookModeFanotifyEbpf, hookModePodInformer:
		parsedHookMode = hookMode
	}

	log.Infof("Parsed hook mode: %s", parsedHookMode)

	return parsedHookMode, nil
}

func hookMode2ccOpts(node, hookMode, nriSocketPath string, fallbackPodInformer bool) ([]containercollection.ContainerCollectionOption, error) {
	var ccOpts []containercollection.ContainerCollectionOption

	podInformerUsed := false
	switch hookMode {
	case "none":
		// CRI-O hooks call the hook-service directly to add and remove containers.
		log.Infof("KubeManager: hook mode: none")
		ccOpts = append(ccOpts, containercollection.WithInitialKubernetesContainers(node))
		ccOpts = append(ccOpts, containercollection.WithOCIConfigForInitialContainer())
	case "auto":
		ccOpts = append(ccOpts, autoHookOption(node, nriSocketPath, fallbackPodInformer))
		podInformerUsed = true
	case "nri":
		log.Infof("KubeManager: hook mode: nri")
		ccOpts = append(ccOpts, containercollection.WithNRI(nriSocketPath))
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

func autoHookOption(node, nriSocketPath string, fallbackPodInformer bool) containercollection.ContainerCollectionOption {
	return func(cc *containercollection.ContainerCollection) error {
		if err := containercollection.WithNRI(nriSocketPath)(cc); err == nil {
			log.Infof("KubeManager: hook mode: nri (auto)")
			if fallbackPodInformer {
				return containercollection.WithFallbackPodInformer(node)(cc)
			}
			return nil
		} else {
			log.Infof("KubeManager: NRI unavailable: %s", err)
		}

		content, err := os.ReadFile("/proc/self/cgroup")
		if err != nil {
			return fmt.Errorf("reading /proc/self/cgroup: %w", err)
		}
		if crioRegex.Match(content) {
			log.Infof("KubeManager: hook mode: crio (auto)")
			if err := installCRIOHooks(); err != nil {
				return fmt.Errorf("installing CRIO hooks: %w", err)
			}
			if err := containercollection.WithInitialKubernetesContainers(node)(cc); err != nil {
				return err
			}
			if err := containercollection.WithOCIConfigForInitialContainer()(cc); err != nil {
				return err
			}
			if fallbackPodInformer {
				return containercollection.WithFallbackPodInformer(node)(cc)
			}
			return nil
		}

		if containerhook.Supported() {
			log.Infof("KubeManager: hook mode: fanotify+ebpf (auto)")
			if err := containercollection.WithContainerFanotifyEbpf()(cc); err != nil {
				return err
			}
			if err := containercollection.WithInitialKubernetesContainers(node)(cc); err != nil {
				return err
			}
			if err := containercollection.WithOCIConfigForInitialContainer()(cc); err != nil {
				return err
			}
			if fallbackPodInformer {
				return containercollection.WithFallbackPodInformer(node)(cc)
			}
			return nil
		}

		log.Infof("KubeManager: hook mode: podinformer (auto)")
		return containercollection.WithPodInformer(node)(cc)
	}
}
