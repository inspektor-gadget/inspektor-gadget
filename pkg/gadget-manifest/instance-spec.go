// Copyright 2024 The Inspektor Gadget authors
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

package gadgetmanifest

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

const (
	APIVersion       = 1
	KindInstanceSpec = "instance-spec"
)

type InstanceSpec struct {
	APIVersion  int               `json:"apiVersion" yaml:"apiVersion"`
	Kind        string            `json:"kind" yaml:"kind"`
	Image       string            `json:"image" yaml:"image"`
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Tags        []string          `json:"tags" yaml:"tags"`
	Nodes       []string          `json:"nodes" yaml:"nodes"`
	ParamValues map[string]string `json:"paramValues" yaml:"paramValues"`
}

func InstanceSpecsFromReader(r io.Reader) ([]*InstanceSpec, error) {
	ydec := yaml.NewDecoder(r)
	res := make([]*InstanceSpec, 0)
	c := 0
	for {
		c++
		spec := &InstanceSpec{}
		err := ydec.Decode(&spec)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing gadget spec (entry %d): %w", c, err)
		}
		if spec == nil {
			continue
		}
		if spec.Kind != KindInstanceSpec {
			return nil, fmt.Errorf("expected kind %q for entry %d in manifest, got kind %q", KindInstanceSpec, c, spec.Kind)
		}
		if spec.APIVersion != APIVersion {
			return nil, fmt.Errorf("expected apiVersion %d for entry %d in manifest, got apiVersion %d", APIVersion, c, spec.APIVersion)
		}
		if spec.ParamValues == nil {
			spec.ParamValues = make(map[string]string)
		}
		if spec.ID != "" && !api.IsValidInstanceID(spec.ID) {
			return nil, fmt.Errorf("invalid instance id %q in entry %d", spec.ID, c)
		}
		if spec.Name != "" && !api.IsValidInstanceName(spec.Name) {
			return nil, fmt.Errorf("invalid instance name %q in entry %d", spec.Name, c)
		}
		for _, t := range spec.Tags {
			if strings.Contains(t, ",") {
				return nil, fmt.Errorf("invalid character \",\" in tag %q of entry %d", t, c)
			}
		}
		if spec.Image == "" {
			return nil, fmt.Errorf("no image specified in entry %d", c)
		}
		res = append(res, spec)
	}
	return res, nil
}
