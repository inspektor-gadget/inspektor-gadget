// Copyright 2023 The Inspektor Gadget authors
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

package oci

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

const ArtifactHubPkgTemplate = `# Artifact Hub package metadata file
# This file was automatically generated from gadget.yaml
version: 0.1.0
name: "{{ .Name }}"
category: monitoring-logging
displayName: "{{ .Name }}"
createdAt: "2000-01-01T08:00:00+01:00"
description: "{{ .Description }}"
logoURL: ""
license: ""
homeURL: "{{ .HomepageURL }}"
containersImages:
    - name: gadget
      image: "{{ image }}"
      platforms:
        - linux/amd64
        - linux/arm64
keywords:
    - gadget
links:
    - name: source
      url: "{{ .SourceURL }}"
install: |
    # Run
    ` + "```" + `bash
    sudo IG_EXPERIMENTAL=true ig run {{ image }}
    ` + "```" + `
provider:
    name: Inspektor Gadget
`

func createOrUpdateArtifactHubPkg(ctx context.Context, opts *BuildGadgetImageOpts) error {
	// load metadata file
	metadataFile, err := os.Open(opts.MetadataPath)
	if err != nil {
		return fmt.Errorf("opening metadata file: %w", err)
	}
	defer metadataFile.Close()

	metadata := &metadatav1.GadgetMetadata{}
	if err := yaml.NewDecoder(metadataFile).Decode(metadata); err != nil {
		return fmt.Errorf("decoding metadata file: %w", err)
	}

	_, statErr := os.Stat(opts.ArtifactHubPkgPath)
	update := statErr == nil

	var artifactHubPkgBytes []byte
	if update {
		// load artifacthub-pkg.yml
		artifactHubPkgBytes, err = os.ReadFile(opts.ArtifactHubPkgPath)
		if err != nil {
			return fmt.Errorf("reading artifact hub pkg file: %w", err)
		}

		log.Debugf("Artifact hub pkg file found, updating it")
	} else {
		log.Debug("Artifact hub pkg file not found, generating it")

		imageFunc := func() string {
			if os.Getenv("IG_ARTIFACTHUB_PKG_IMAGE") != "" {
				return os.Getenv("IG_ARTIFACTHUB_PKG_IMAGE")
			}
			return "TODO"
		}

		funcMap := template.FuncMap{
			"image": imageFunc,
		}

		t, err := template.New("artifacthub-pkg.yml").Funcs(funcMap).Parse(ArtifactHubPkgTemplate)
		if err != nil {
			return fmt.Errorf("parsing artifact hub pkg template: %w", err)
		}
		var doc bytes.Buffer
		t.Execute(&doc, metadata)

		artifactHubPkgBytes = []byte(doc.String())
	}

	var artifactHubPkg yaml.Node
	err = yaml.Unmarshal(artifactHubPkgBytes, &artifactHubPkg)
	if err != nil {
		return fmt.Errorf("unmarshalling artifact hub pkg file: %w\n%s", err, string(artifactHubPkgBytes))
	}

	if artifactHubPkg.Kind != yaml.DocumentNode {
		return errors.New("artifact hub pkg file is not a document")
	}
	if len(artifactHubPkg.Content) == 0 {
		return errors.New("artifact hub pkg file is empty")
	}
	if artifactHubPkg.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("artifact hub pkg file top level data structure is not a mapping: %v", artifactHubPkg.Content[0].Kind)
	}
	if len(artifactHubPkg.Content[0].Content)%2 != 0 {
		return fmt.Errorf("artifact hub pkg file has an odd amount (%d) of keys and values", len(artifactHubPkg.Content[0].Content))
	}

	// Update metadata.
	// Mappings have an even number of elements (keys+values). We just checked
	// that above. So we can safely iterate by 2.
	for i := 0; i < len(artifactHubPkg.Content[0].Content)/2; i++ {
		key := artifactHubPkg.Content[0].Content[i*2]
		value := artifactHubPkg.Content[0].Content[i*2+1]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		if value.Kind != yaml.ScalarNode {
			continue
		}
		switch key.Value {
		case "name":
			value.Value = metadata.Name
		case "displayName":
			value.Value = metadata.Name
		case "description":
			value.Value = metadata.Description
		case "homepageURL":
			value.Value = metadata.HomepageURL
		case "createdAt":
			value.Value = opts.CreatedDate
		default:
			if ann, ok := metadata.Annotations["artifacthub.io/"+key.Value]; ok {
				value.Value = ann
			}
			env := os.Getenv("IG_ARTIFACTHUB_PKG_" + strings.ToUpper(key.Value))
			if env != "" {
				value.Value = env
			}
		}
	}

	marshalled, err := yaml.Marshal(artifactHubPkg.Content[0])
	if err != nil {
		return err
	}

	if err := os.WriteFile(opts.ArtifactHubPkgPath, marshalled, 0o644); err != nil {
		return fmt.Errorf("writing artifact hub pkg file: %w", err)
	}

	// fix owner of created artifact hub pkg file
	if !update {
		if err := fixOwner(opts.ArtifactHubPkgPath, opts.EBPFSourcePath); err != nil {
			log.Warnf("Failed to fix artifact hub pkg file owner: %v", err)
		}
	}

	return nil
}
