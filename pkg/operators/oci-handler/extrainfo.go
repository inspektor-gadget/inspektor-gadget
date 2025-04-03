package ocihandler

import (
	"encoding/json"
	"fmt"

	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"sigs.k8s.io/kustomize/kyaml/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type Config struct {
	Name             string                      `yaml:"name"`
	Description      string                      `yaml:"description"`
	HomepageURL      string                      `yaml:"homepageURL"`
	DocumentationURL string                      `yaml:"documentationURL"`
	SourceURL        string                      `yaml:"sourceURL"`
	Datasources      map[string]Datasource       `yaml:"datasources"`
	Params           map[string]map[string]Param `yaml:"params"`
}

type Datasource struct {
	Fields map[string]Field `yaml:"fields"`
}

type Field struct {
	Annotations map[string]interface{} `yaml:"annotations"`
}

type Param struct {
	Key          string `yaml:"key"`
	DefaultValue string `yaml:"defaultValue"`
	Description  string `yaml:"description"`
}

func addExtraInfo(gadgetCtx operators.GadgetContext, metadata []byte, manifest *ocispec.Manifest) {
	parsed, err := reference.Parse(gadgetCtx.ImageName())
	if err != nil {
		fmt.Println("Error parsing image name")
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

	var config Config
	if err := yaml.Unmarshal(metadata, &config); err != nil {
		fmt.Printf("Error unmarshalling metadata: %v\n", err)
	}

	ociInfo := &api.ExtraInfo{
		Data: make(map[string]*api.GadgetInspectAddendum),
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

	layersJson, _ := json.Marshal(layers)
	ociInfo.Data["oci.layers"] = &api.GadgetInspectAddendum{
		ContentType: "application/json",
		Content:     []byte(fmt.Sprintf("%v", string(layersJson))),
	}

	gadgetCtx.SetVar("extraInfo.oci", ociInfo)
}
