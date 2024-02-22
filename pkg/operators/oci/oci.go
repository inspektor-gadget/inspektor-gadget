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
	"fmt"

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

// OciHandler bridges our legacy operator system with the image based gadgets
// once we remove the legacy gadgets, this operator should be called directly as if it
// were the gadget
type OciHandler struct{}

func (o *OciHandler) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		// Hardcoded for now
		{
			Key:          authfileParam,
			Title:        "Auth file",
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

func (o *OciHandler) Instantiate(gadgetCtx operators.GadgetContext, params *params.Params, args []string) (*OciHandlerInstance, error) {
	//panic("not to be called")

	if len(args) != 1 {
		return nil, fmt.Errorf("URL required as argument")
	}
	imageName := args[0]

	secretBytes := []byte{} // TODO

	authOpts := &oci.AuthOptions{
		AuthFile:    params.Get(authfileParam).AsString(),
		SecretBytes: secretBytes,
		Insecure:    params.Get(insecureParam).AsBool(),
	}

	// Make sure the image is available, either through pulling or by just accessing a local copy
	// TODO: add security constraints (e.g. don't allow pulling - add GlobalParams for that)
	err := oci.EnsureImage(gadgetCtx.Context(), imageName, authOpts, params.Get(pullParam).AsString())
	if err != nil {
		return nil, fmt.Errorf("insuring image: %w", err)
	}

	manifest, err := oci.GetManifestForHost(gadgetCtx.Context(), imageName)
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
	// err = yaml.NewDecoder(r).Decode(metadata)

	viper := viper.New()
	viper.SetConfigType("yaml")
	err = viper.ReadConfig(r)

	// d, _ := io.ReadAll(r)
	// logger.Debugf("%s", string(d))
	// err = yaml.Unmarshal(d, &metadata)
	r.Close()
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
			instance.layerOperatorInstances = append(instance.layerOperatorInstances, opInst)
			if opInst == nil {
				logger.Debugf("> skipped %s", op.Name())
				continue
			}
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

	return instance, nil
}

//func (o *OciHandlerInstance) ParamDescs() params.ParamDescs {
//	return nil
//}

func (o *OciHandlerInstance) PrepareOps() error {
	// Prepare
	for _, opInst := range o.layerOperatorInstances {
		err := opInst.Prepare(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("preparing operator %q: %v", opInst.Name(), err)
		}
	}
	for _, opInst := range o.dataOperatorInstances {
		err := opInst.Prepare(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("preparing operator %q: %v", opInst.Name(), err)
		}
	}
	return nil
}

func (o *OciHandlerInstance) StartOps() error {
	//panic("not to be called")

	// Run
	for _, opInst := range o.layerOperatorInstances {
		err := opInst.Start(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("starting operator %q: %v", opInst.Name(), err)
		}
	}
	for _, opInst := range o.dataOperatorInstances {
		err := opInst.Start(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("starting operator %q: %v", opInst.Name(), err)
		}
	}
	return nil
}

func (o *OciHandlerInstance) Stop() error {
	return nil
}

type OciHandlerInstance struct {
	gadgetCtx              operators.GadgetContext
	layerOperatorInstances []operators.ImageOperatorInstance
	dataOperatorInstances  []operators.DataOperatorInstance
}
