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

package main

import (
	"encoding/json"
	"slices"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"

	seccomp "main/seccomp"
)

const (
	// config.json is typically less than 100 KiB.
	// 1 MiB should be enough.
	configJsonMaxSize = 1 * 1024 * 1024
)

func updateConfig(configText string) string {
	config := &ocispec.Spec{}
	err := json.Unmarshal([]byte(configText), config)
	if err != nil {
		api.Errorf("unmarshaling config.json: %s", err)
		return ""
	}

	if config.Linux == nil {
		api.Errorf("Linux config is nil\n")
		return ""
	}
	if config.Linux.Seccomp == nil {
		api.Debugf("Seccomp config is nil. Creating one from containerd.\n")
		sp := seccomp.DefaultProfile(config)
		if !slices.Contains(sp.Flags, ocispec.LinuxSeccompFlagLog) {
			sp.Flags = append(sp.Flags, ocispec.LinuxSeccompFlagLog)
		}
		config.Linux.Seccomp = sp
	} else {
		if slices.Contains(config.Linux.Seccomp.Flags, ocispec.LinuxSeccompFlagLog) {
			api.Debugf("Seccomp config already has log flag\n")
			return ""
		}
		config.Linux.Seccomp.Flags = append(config.Linux.Seccomp.Flags, ocispec.LinuxSeccompFlagLog)
	}

	newConfigBytes, err := json.Marshal(config)
	if err != nil {
		api.Errorf("marshaling config.json: %s", err)
		return ""
	}
	return string(newConfigBytes)
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	ds, err := api.GetDataSource("containers")
	if err != nil {
		api.Errorf("Failed to get data source: %v", err)
		return 1
	}

	eventTypeField, err := ds.GetField("event_type")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	containerConfigField, err := ds.GetField("container_config")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	idField, err := ds.GetField("container_id")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	ds.Subscribe(func(ds api.DataSource, data api.Data) {
		eventType, err := eventTypeField.String(data, 9)
		if err != nil {
			api.Errorf("getting event_type from corresponding field: %v", err)
			return
		}
		if eventType != "PRECREATE" {
			return
		}
		configText, err := containerConfigField.String(data, configJsonMaxSize)
		if err != nil {
			api.Errorf("getting container_config from corresponding field: %v", err)
			return
		}

		newConfigText := updateConfig(configText)
		if newConfigText != "" {
			containerConfigField.SetString(data, newConfigText)
			id, _ := idField.String(data, 64)
			api.Debugf("Gadget audit_seccomp modified OCI config of container %s", id)
		}
	}, 0)

	return 0
}

func main() {}
