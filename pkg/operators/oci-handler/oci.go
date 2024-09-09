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

package ocihandler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"text/template"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/resources"
)

const (
	validateMetadataParam   = "validate-metadata"
	authfileParam           = "authfile"
	insecureRegistriesParam = "insecure-registries"
	disallowPulling         = "disallow-pulling"
	pullParam               = "pull"
	pullSecret              = "pull-secret"
	verifyImage             = "verify-image"
	publicKeys              = "public-keys"
	allowedGadgets          = "allowed-gadgets"
)

type ociHandler struct {
	globalParams *params.Params
}

func (o *ociHandler) Name() string {
	return "oci"
}

func (o *ociHandler) Init(params *params.Params) error {
	o.globalParams = params
	return nil
}

func (o *ociHandler) GlobalParams() api.Params {
	return api.Params{
		{
			Key:          verifyImage,
			Title:        "Verify image",
			Description:  "Verify image using the provided public key",
			DefaultValue: "true",
			TypeHint:     api.TypeBool,
		},
		{
			Key:          publicKeys,
			Title:        "Public keys",
			Description:  "Public keys used to verify the gadgets",
			DefaultValue: resources.InspektorGadgetPublicKey,
			TypeHint:     api.TypeStringSlice,
		},
		{
			Key:         allowedGadgets,
			Title:       "Allowed Gadgets",
			Description: "List of allowed gadgets, if gadget is not part of it, execution will be denied. By default, all digests are allowed",
			TypeHint:    api.TypeStringSlice,
		},
		{
			Key:         insecureRegistriesParam,
			Title:       "Insecure registries",
			Description: "List of registries to access over plain HTTP",
			TypeHint:    api.TypeStringSlice,
		},
		{
			Key:         disallowPulling,
			Title:       "Disallow pulling",
			Description: "Disallow pulling gadgets from registries",
			TypeHint:    api.TypeBool,
		},
	}
}

func (o *ociHandler) InstanceParams() api.Params {
	return api.Params{
		// Hardcoded for now
		{
			Key:          authfileParam,
			Title:        "Auth file",
			Description:  "Path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable",
			DefaultValue: oci.DefaultAuthFile,
			TypeHint:     api.TypeString,
		},
		{
			Key:          validateMetadataParam,
			Title:        "Validate metadata",
			Description:  "Validate the gadget metadata before running the gadget",
			DefaultValue: "true",
			TypeHint:     api.TypeBool,
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
			TypeHint: api.TypeString,
		},
		{
			Key:         pullSecret,
			Title:       "Pull secret",
			Description: "Secret to use when pulling the gadget image",
			TypeHint:    api.TypeString,
		},
	}
}

func getPullSecret(pullSecretString string, gadgetNamespace string) ([]byte, error) {
	k8sClient, err := k8sutil.NewClientset("")
	if err != nil {
		return nil, fmt.Errorf("creating new k8s clientset: %w", err)
	}
	gps, err := k8sClient.CoreV1().Secrets(gadgetNamespace).Get(context.TODO(), pullSecretString, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting secret %q: %w", pullSecretString, err)
	}
	if gps.Type != corev1.SecretTypeDockerConfigJson {
		return nil, fmt.Errorf("secret %q is not of type %q", pullSecretString, corev1.SecretTypeDockerConfigJson)
	}
	return gps.Data[corev1.DockerConfigJsonKey], nil
}

func (o *ociHandler) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (
	operators.DataOperatorInstance, error,
) {
	ociParams := o.globalParams
	if ociParams == nil {
		ociParams = apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	}

	*ociParams = append(*ociParams, *apihelpers.ToParamDescs(o.InstanceParams()).ToParams()...)
	err := ociParams.CopyFromMap(instanceParamValues, "")
	if err != nil {
		return nil, err
	}

	instance := &OciHandlerInstance{
		ociHandler:  o,
		gadgetCtx:   gadgetCtx,
		ociParams:   ociParams,
		paramValues: instanceParamValues,
		extraParams: make([]*api.Param, 0),
	}

	err = instance.init(gadgetCtx)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (o *OciHandlerInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	return o.extraParams
}

func (o *OciHandlerInstance) init(gadgetCtx operators.GadgetContext) error {
	if len(gadgetCtx.ImageName()) == 0 {
		return fmt.Errorf("imageName empty")
	}

	// TODO: move to a place without dependency on k8s
	pullSecretString := o.ociParams.Get(pullSecret).AsString()
	var secretBytes []byte = nil
	if pullSecretString != "" {
		var err error
		// TODO: Namespace is still hardcoded
		secretBytes, err = getPullSecret(pullSecretString, "gadget")
		if err != nil {
			return err
		}
	}

	imgOpts := &oci.ImageOptions{
		AuthOptions: oci.AuthOptions{
			AuthFile:           o.ociParams.Get(authfileParam).AsString(),
			SecretBytes:        secretBytes,
			InsecureRegistries: o.ociParams.Get(insecureRegistriesParam).AsStringSlice(),
			DisallowPulling:    o.ociParams.Get(disallowPulling).AsBool(),
		},
		VerifyOptions: oci.VerifyOptions{
			VerifyPublicKey: o.ociParams.Get(verifyImage).AsBool(),
			PublicKeys:      o.ociParams.Get(publicKeys).AsStringSlice(),
		},
		AllowedGadgetsOptions: oci.AllowedGadgetsOptions{
			AllowedGadgets: o.ociParams.Get(allowedGadgets).AsStringSlice(),
		},
		Logger: gadgetCtx.Logger(),
	}

	gadgetCtx.Logger().Debugf("image options: %+v", imgOpts)

	target := gadgetCtx.OrasTarget()
	// If the target wasn't explicitly set, use the local store. In this case we
	// need to be sure the image is available.
	if target == nil {
		var err error
		target, err = oci.GetLocalOciStore()
		if err != nil {
			return fmt.Errorf("getting local oci store: %w", err)
		}

		// Make sure the image is available, either through pulling or by just accessing a local copy
		// TODO: add security constraints (e.g. don't allow pulling - add GlobalParams for that)
		err = oci.EnsureImage(gadgetCtx.Context(), gadgetCtx.ImageName(),
			imgOpts, o.ociParams.Get(pullParam).AsString())
		if err != nil {
			return fmt.Errorf("ensuring image: %w", err)
		}
	}

	manifest, err := oci.GetManifestForHost(gadgetCtx.Context(), target, gadgetCtx.ImageName())
	if err != nil {
		return fmt.Errorf("getting manifest: %w", err)
	}

	log := gadgetCtx.Logger()

	r, err := oci.GetContentFromDescriptor(gadgetCtx.Context(), target, manifest.Config)
	if err != nil {
		return fmt.Errorf("getting metadata: %w", err)
	}
	metadata, err := io.ReadAll(r)
	if err != nil {
		r.Close()
		return fmt.Errorf("reading metadata: %w", err)
	}
	r.Close()

	// Store metadata for serialization
	gadgetCtx.SetMetadata(metadata)

	viper := viper.New()
	viper.SetConfigType("yaml")
	err = viper.ReadConfig(bytes.NewReader(metadata))
	if err != nil {
		return fmt.Errorf("unmarshalling metadata: %w", err)
	}

	// Extract custom params
	customParams := viper.Sub("params.custom")
	if customParams != nil {
		for k := range viper.GetStringMap("params.custom") {
			log.Debugf("evaluating custom param %q", k)
			paramSub := customParams.Sub(k)
			valuesSub := paramSub.Sub("values")
			if valuesSub == nil {
				log.Debugf("custom param %q has no values", k)
				continue
			}
			p := &api.Param{
				Key:          k,
				Description:  paramSub.GetString("description"),
				Prefix:       "custom.",
				DefaultValue: paramSub.GetString("defaultValue"),
			}
			for value := range paramSub.GetStringMap("values") {
				// Skip wildcard param
				if value == "*" {
					continue
				}
				p.PossibleValues = append(p.PossibleValues, value)
			}
			o.extraParams = append(o.extraParams, p)

			// Evaluate, if set
			if val, ok := o.paramValues["custom."+k]; ok {
				valName := val
				if !paramSub.IsSet("values."+valName+".applyConfig") && paramSub.IsSet("values.*.applyConfig") {
					// Use wildcard fallback
					valName = "*"
				}

				log.Debugf("applying custom param %q value %q", k, valName)

				valSub := paramSub.Sub("values." + valName + ".applyConfig")
				if valSub == nil {
					continue
				}

				// Apply templates
				replacements := make(map[string]string)
				for _, k1 := range valSub.AllKeys() {
					v1 := valSub.Get(k1)
					if s, ok := v1.(string); ok {
						tpl, err := template.New(k1).Parse(s)
						if err != nil {
							return fmt.Errorf("parsing custom param %q value %q: %q cannot be parsed as template: %w", k, val, k1, err)
						}
						out := bytes.NewBuffer(nil)
						err = tpl.Execute(out, map[string]any{
							"paramValues": o.paramValues,
							"getConfig": func(key string) string {
								return viper.GetString(key)
							},
						})
						if err != nil {
							return fmt.Errorf("evaluating custom param %q value %q template for %q: %w", k, val, k1, err)
						}
						if tplOut := out.String(); tplOut != s {
							replacements[k1] = tplOut
						}
					}
				}

				for k1, v1 := range replacements {
					log.Debugf("replacing %q with %q", k1, v1)
					paramSub.Set("values."+valName+".applyConfig."+k1, v1)
				}

				applyMap := paramSub.GetStringMap("values." + valName + ".applyConfig")

				// Prevent recursive patching of customparams
				delete(applyMap, "customparams")

				// Merge with config
				err = viper.MergeConfigMap(applyMap)
				if err != nil {
					return fmt.Errorf("merging custom param %q value %q: %w", k, valName, err)
				}
			}
		}
	}

	gadgetCtx.SetVar("config", viper)

	for _, layer := range manifest.Layers {
		log.Debugf("layer > %+v", layer)
		op, ok := operators.GetImageOperatorForMediaType(layer.MediaType)
		if !ok {
			continue
		}

		log.Debugf("found image op %q", op.Name())
		opInst, err := op.InstantiateImageOperator(gadgetCtx, target, layer, o.paramValues.ExtractPrefixedValues(op.Name()))
		if err != nil {
			log.Errorf("instantiating operator %q: %v", op.Name(), err)
		}
		if opInst == nil {
			log.Debugf("> skipped %s", op.Name())
			continue
		}
		o.imageOperatorInstances = append(o.imageOperatorInstances, opInst)
	}

	if len(o.imageOperatorInstances) == 0 {
		return fmt.Errorf("image doesn't contain valid gadget layers")
	}

	for _, opInst := range o.imageOperatorInstances {
		err := opInst.Prepare(o.gadgetCtx)
		if err != nil {
			return fmt.Errorf("preparing operator %q: %w", opInst.Name(), err)
		}

		// Add gadget params prefixed with operators' name
		o.extraParams = append(o.extraParams, opInst.ExtraParams(gadgetCtx).AddPrefix(opInst.Name())...)
	}

	return nil
}

func (o *OciHandlerInstance) Start(gadgetCtx operators.GadgetContext) error {
	started := []operators.ImageOperatorInstance{}

	for _, opInst := range o.imageOperatorInstances {
		err := opInst.Start(o.gadgetCtx)
		if err != nil {
			// Stop all started operators
			for _, startedOp := range started {
				startedOp.Stop(o.gadgetCtx)
			}

			return fmt.Errorf("starting operator %q: %w", opInst.Name(), err)
		}

		started = append(started, opInst)
	}
	return nil
}

func (o *OciHandlerInstance) Stop(gadgetCtx operators.GadgetContext) error {
	for _, opInst := range o.imageOperatorInstances {
		err := opInst.Stop(o.gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("stopping operator %q: %v", opInst.Name(), err)
		}
	}
	return nil
}

type OciHandlerInstance struct {
	ociHandler             *ociHandler
	gadgetCtx              operators.GadgetContext
	imageOperatorInstances []operators.ImageOperatorInstance
	extraParams            api.Params
	paramValues            api.ParamValues
	ociParams              *params.Params
}

func (o *OciHandlerInstance) Name() string {
	return "oci"
}

func (o *ociHandler) Priority() int {
	return -1000
}

// OciHandler is a singleton of ociHandler
var OciHandler = &ociHandler{}
