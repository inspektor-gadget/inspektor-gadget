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

package ocihandler

import (
	"encoding/json"
	"fmt"

	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func addExtraInfo(gadgetCtx operators.GadgetContext, metadata []byte, manifest *ocispec.Manifest) error {
	parsed, err := reference.Parse(gadgetCtx.ImageName())
	if err != nil {
		return err
	}

	var repository string
	if named, ok := parsed.(reference.Named); ok {
		repository = named.Name()
	}

	tag := "latest"
	if tagged, ok := parsed.(reference.Tagged); ok {
		tag = tagged.Tag()
	}

	digest := ""
	if digested, ok := parsed.(reference.Digested); ok {
		digest = digested.Digest().String()
	}

	created := manifest.Annotations[ocispec.AnnotationCreated]

	layers := []string{}
	for i := 0; i < len(manifest.Layers); i++ {
		layers = append(layers, manifest.Layers[i].MediaType)
	}

	ociData := make(map[string]*api.ExtraInfoData)

	manifestJson, _ := json.Marshal(manifest)
	ociData["manifest"] = &api.ExtraInfoData{
		ContentType: "application/json",
		Content:     manifestJson,
	}
	ociData["metadata"] = &api.ExtraInfoData{
		ContentType: "text/yaml",
		Content:     metadata,
	}
	ociData["repository"] = &api.ExtraInfoData{
		ContentType: "text/plain",
		Content:     []byte(repository),
	}
	ociData["tag"] = &api.ExtraInfoData{
		ContentType: "text/plain",
		Content:     []byte(tag),
	}
	ociData["digest"] = &api.ExtraInfoData{
		ContentType: "text/plain",
		Content:     []byte(digest),
	}
	ociData["created"] = &api.ExtraInfoData{
		ContentType: "text/plain",
		Content:     []byte(created),
	}

	layersJson, _ := json.Marshal(layers)
	ociData["layers"] = &api.ExtraInfoData{
		ContentType: "application/json",
		Content:     []byte(fmt.Sprintf("%v", string(layersJson))),
	}

	gadgetCtx.SetVar("extraInfo.oci", ociData)

	return nil
}
