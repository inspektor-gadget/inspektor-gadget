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
	"encoding/json"
	"os"
	"path/filepath"

	nriv1 "github.com/containerd/nri/types/v1"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func removeCRIOHooks() {
	for _, file := range []string{"ocihookgadget", "prestart.sh", "poststop.sh"} {
		path := filepath.Join("/opt/hooks/oci", file)
		hostPath := filepath.Join(host.HostRoot, path)
		os.Remove(hostPath)
	}

	for _, file := range []string{"etc/containers/oci/hooks.d", "usr/share/containers/oci/hooks.d/"} {
		hookPath := filepath.Join(host.HostRoot, file)
		for _, config := range []string{"gadget-prestart.json", "gadget-poststop.json"} {
			path := filepath.Join(hookPath, config)
			os.Remove(path)
		}
	}
}

func removeNRIHooks() {
	path := filepath.Join(host.HostRoot, "opt/nri/bin/nrigadget")
	os.Remove(path)

	configPath := filepath.Join(host.HostRoot, "etc/nri/conf.json")
	content, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	var configList nriv1.ConfigList
	err = json.Unmarshal(content, &configList)
	if err != nil {
		return
	}

	length := len(configList.Plugins)
	if length == 1 && configList.Plugins[0].Type == "nrigadget" {
		os.Remove(configPath)
	} else {
		for i, plugin := range configList.Plugins {
			if plugin.Type != "nrigadget" {
				continue
			}

			configList.Plugins[i] = configList.Plugins[length-1]
			configList.Plugins = configList.Plugins[:length-1]

			break
		}

		content, err = json.Marshal(configList)
		if err != nil {
			return
		}

		err = os.WriteFile(configPath, content, 0o640)
		if err != nil {
			return
		}
	}
}

func main() {
	removeCRIOHooks()
	removeNRIHooks()

	os.RemoveAll("/sys/fs/bpf/gadget/")

	log.Infof("Cleanup completed")
}
