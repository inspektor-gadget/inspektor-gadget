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

package ocioperator

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	validateMetadataParam = "validate-metadata"
	authfileParam         = "authfile"
	insecureParam         = "insecure"
	pullParam             = "pull"
	pullSecret            = "pull-secret"
)

// ociHandler bridges our legacy operator system with the image based gadgets
// once we remove the legacy gadgets, this operator should be called directly as if it
// were the gadget
type ociHandler struct{}

func (o *ociHandler) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		// Hardcoded for now
		{
			Key:          authfileParam,
			Title:        "Auth file",
			Description:  "Path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable",
			DefaultValue: oci.DefaultAuthFile,
			TypeHint:     params.TypeString,
		},
		{
			Key:          validateMetadataParam,
			Title:        "Validate metadata",
			Description:  "Validate the gadget metadata before running the gadget",
			DefaultValue: "true",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          insecureParam,
			Title:        "Insecure connection",
			Description:  "Allow connections to HTTP only registries",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          pullParam,
			Title:        "Pull policy",
			Description:  "Specify when the gadget image should be pulled",
			DefaultValue: oci.PullImageMissing,
			PossibleValues: []string{
				oci.PullImageAlways,
				oci.PullImageMissing,
				oci.PullImageNever,
			},
			TypeHint: params.TypeString,
		},
		{
			Key:         pullSecret,
			Title:       "Pull secret",
			Description: "Secret to use when pulling the gadget image",
			TypeHint:    params.TypeString,
		},
	}
}

func (o *ociHandler) Instantiate(gadgetCtx operators.GadgetContext, params *params.Params) (*OciHandlerInstance, error) {
	if len(gadgetCtx.ImageName()) == 0 {
		return nil, fmt.Errorf("imageName empty")
	}

	secretBytes := []byte{} // TODO

	authOpts := &oci.AuthOptions{
		AuthFile:    params.Get(authfileParam).AsString(),
		SecretBytes: secretBytes,
		Insecure:    params.Get(insecureParam).AsBool(),
	}

	// Make sure the image is available, either through pulling or by just accessing a local copy
	// TODO: add security constraints (e.g. don't allow pulling - add GlobalParams for that)
	err := oci.EnsureImage(gadgetCtx.Context(), gadgetCtx.ImageName(), authOpts, params.Get(pullParam).AsString())
	if err != nil {
		return nil, fmt.Errorf("insuring image: %w", err)
	}

	manifest, err := oci.GetManifestForHost(gadgetCtx.Context(), gadgetCtx.ImageName())
	if err != nil {
		return nil, fmt.Errorf("getting manifest: %w", err)
	}

	logger := gadgetCtx.Logger()
	logger.Debugf("ArtifactType: %s", manifest.ArtifactType)

	// metadata := &types.GadgetMetadata{}
	r, err := oci.GetContentFromDescriptor(gadgetCtx.Context(), manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("getting metadata: %w", err)
	}
	metadata, _ := io.ReadAll(r)
	r.Close()

	// Store metadata for serialization
	gadgetCtx.SetMetadata(metadata)

	viper := viper.New()
	viper.SetConfigType("yaml")
	err = viper.ReadConfig(bytes.NewReader(metadata))

	if err != nil {
		return nil, fmt.Errorf("unmarshalling metadata: %w", err)
	}

	gadgetCtx.SetVar("config", viper)

	instance := &OciHandlerInstance{
		gadgetCtx: gadgetCtx,
	}

	for _, layer := range manifest.Layers {
		logger.Debugf("layer > %+v", layer)
		ops := operators.GetImageOperatorsForMediaType(layer.MediaType)
		for _, op := range ops {
			logger.Debugf("found layer op %q", op.Name())
			opInst, err := op.InstantiateImageOperator(gadgetCtx, layer)
			if err != nil {
				logger.Errorf("instantiating operator %q: %v", op.Name(), err)
			}
			if opInst == nil {
				logger.Debugf("> skipped %s", op.Name())
				continue
			}
			instance.layerOperatorInstances = append(instance.layerOperatorInstances, opInst)
		}
	}

	for _, op := range operators.GetDataOperators() {
		logger.Debugf("found data op %q", op.Name())

		// Lazily initialize operator
		err := op.Init(op.GlobalParamDescs().ToParams())
		if err != nil {
			return nil, fmt.Errorf("initializing operator %q: %w", op.Name(), err)
		}

		opInst, err := op.InstantiateDataOperator(gadgetCtx)
		if err != nil {
			logger.Errorf("instantiating operator %q: %v", op.Name(), err)
		}
		if opInst == nil {
			logger.Debugf("> skipped %s", op.Name())
			continue
		}
		instance.dataOperatorInstances = append(instance.dataOperatorInstances, opInst)
	}

	// Sort dataOperators based on their priority
	sort.Slice(instance.dataOperatorInstances, func(i, j int) bool {
		return instance.dataOperatorInstances[i].Priority() < instance.dataOperatorInstances[j].Priority()
	})

	return instance, nil
}

func (o *OciHandlerInstance) ParamDescs() params.ParamDescs {
	return nil
}

func (o *OciHandlerInstance) Prepare() error {
	for _, opInst := range o.layerOperatorInstances {
		err := opInst.Prepare(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("preparing operator %q: %v", opInst.Name(), err)
		}
	}

	// First pass: get params
	for _, opInst := range o.dataOperatorInstances {
		pd := opInst.ParamDescs(o.gadgetCtx)
		for _, p := range pd {
			o.gadgetCtx.Logger().Debugf("op-param 1st %s => %s", p.Key, p.DefaultValue)
		}
		// Write param contents that we know about
		// o.gadgetCtx.RegisterParam(&api.Param{
		// 	Key:            "",
		// 	Description:    "",
		// 	DefaultValue:   "",
		// 	TypeHint:       "",
		// 	Title:          "",
		// 	Alias:          "",
		// 	Tags:           nil,
		// 	ValueHint:      "",
		// 	PossibleValues: nil,
		// 	IsMandatory:    false,
		// })
	}

	for _, opInst := range o.dataOperatorInstances {
		err := opInst.Prepare(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("preparing operator %q: %v", opInst.Name(), err)
			continue
		}

		// Second pass params
		pd := opInst.ParamDescs(o.gadgetCtx)
		for _, p := range pd {
			o.gadgetCtx.Logger().Debugf("op-param 2nd %s => %s", p.Key, p.DefaultValue)
		}
	}
	return nil
}

func (o *OciHandlerInstance) PreGadgetRun() error {
	// Run
	for _, opInst := range o.dataOperatorInstances {
		err := opInst.Start(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("starting operator %q: %v", opInst.Name(), err)
		}
	}
	for _, opInst := range o.layerOperatorInstances {
		err := opInst.Start(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("starting operator %q: %v", opInst.Name(), err)
		}
	}
	return nil
}

func (o *OciHandlerInstance) PostGadgetRun() error {
	for _, opInst := range o.layerOperatorInstances {
		err := opInst.Stop(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("starting operator %q: %v", opInst.Name(), err)
		}
	}
	for _, opInst := range o.dataOperatorInstances {
		err := opInst.Stop(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("stopping operator %q: %v", opInst.Name(), err)
		}
	}
	return nil
}

type OciHandlerInstance struct {
	gadgetCtx              operators.GadgetContext
	layerOperatorInstances []operators.ImageOperatorInstance
	dataOperatorInstances  []operators.DataOperatorInstance
}

// OciHandler is a singleton of ociHandler
var OciHandler = &ociHandler{}
