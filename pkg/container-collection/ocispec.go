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

// This file provides lightweight functions to parse the OCI config
// The oci config is expected to be in the format of
// https://github.com/opencontainers/runtime-spec/blob/v1.2.1/specs-go/config.go#L18

package containercollection

import (
	"encoding/json"
)

// ociConfigGetSourceMounts returns the source mounts from the oci config
func ociConfigGetSourceMounts(ociConfig string) (out []string, err error) {
	var config struct {
		Mounts []struct {
			Source string `json:"source,omitempty"`
		} `json:"mounts,omitempty"`
	}
	err = json.Unmarshal([]byte(ociConfig), &config)
	if err != nil {
		return nil, err
	}
	for _, m := range config.Mounts {
		out = append(out, m.Source)
	}
	return out, nil
}

// ociConfigGetAnnotations returns the annotations from the oci config
func ociConfigGetAnnotations(ociConfig string) (map[string]string, error) {
	var config struct {
		Annotations map[string]string `json:"annotations,omitempty"`
	}
	err := json.Unmarshal([]byte(ociConfig), &config)
	if err != nil {
		return nil, err
	}
	return config.Annotations, nil
}
