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

	digest := manifest.Config.Digest.String()

	created := manifest.Annotations[ocispec.AnnotationCreated]

	ociInfo := &api.ExtraInfo{
		Data: make(map[string]*api.GadgetInspectAddendum),
	}
	manifestJson, _ := json.Marshal(manifest)
	ociInfo.Data["oci.manifest"] = &api.GadgetInspectAddendum{
		ContentType: "application/json",
		Content:     manifestJson,
	}
	ociInfo.Data["oci.metadata"] = &api.GadgetInspectAddendum{
		ContentType: "text/yaml",
		Content:     metadata,
	}
	ociInfo.Data["oci.repository"] = &api.GadgetInspectAddendum{
		ContentType: "text/plain",
		Content:     []byte(repository),
	}
	ociInfo.Data["oci.tag"] = &api.GadgetInspectAddendum{
		ContentType: "text/plain",
		Content:     []byte(tag),
	}
	ociInfo.Data["oci.digest"] = &api.GadgetInspectAddendum{
		ContentType: "text/plain",
		Content:     []byte(digest),
	}
	ociInfo.Data["oci.created"] = &api.GadgetInspectAddendum{
		ContentType: "text/plain",
		Content:     []byte(created),
	}

	gadgetCtx.SetVar("extraInfo.oci", ociInfo)

	return nil
}
