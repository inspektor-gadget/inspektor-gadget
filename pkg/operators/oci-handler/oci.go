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
	"slices"
	"strings"

	"github.com/blang/semver"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
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
	annotate                = "annotate"
	verifyImage             = "verify-image"
	publicKeys              = "public-keys"
	allowedGadgets          = "allowed-gadgets"
)

const (
	builderVersionAnnotation = "io.inspektor-gadget.builder.version"
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
	p := api.Params{
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
			Key:          disallowPulling,
			Title:        "Disallow pulling",
			Description:  "Disallow pulling gadgets from registries",
			DefaultValue: "false",
			TypeHint:     api.TypeBool,
		},
		{
			Key:          authfileParam,
			Title:        "Auth file",
			Description:  "Path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable",
			DefaultValue: oci.DefaultAuthFile,
			TypeHint:     api.TypeString,
		},
	}

	if environment.Environment == environment.Kubernetes {
		p = append(p, &api.Param{
			Key:         pullSecret,
			Title:       "Pull secret",
			Description: "Kubernetes secret to use when pulling the gadget image",
			TypeHint:    api.TypeString,
		})
	}

	return p
}

func (o *ociHandler) InstanceParams() api.Params {
	return api.Params{
		// Hardcoded for now
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
			Key:   annotate,
			Title: "Add annotations",
			Description: "Add annotations to datasources or fields. Use a comma-separated list in the formats:\n" +
				"  'datasource:annotation=value' to add an annotation to a datasource.\n" +
				"  'datasource.field:annotation=value' to add an annotation to the field of a datasource\n",
			TypeHint: api.TypeStringSlice,
		},
	}
}

func getPullSecret(pullSecretString string, gadgetNamespace string, k8sClient kubernetes.Interface) ([]byte, error) {
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
	// TODO: This should be moved to Init(), but we're relying on Init() not
	// being called in many places, specially tests and examples.
	if o.globalParams == nil {
		o.globalParams = apihelpers.ToParamDescs(o.GlobalParams()).ToParams()
	}

	instanceParams := apihelpers.ToParamDescs(o.InstanceParams()).ToParams()
	err := instanceParams.CopyFromMap(instanceParamValues, "")
	if err != nil {
		return nil, err
	}

	instance := &OciHandlerInstance{
		ociHandler:     o,
		gadgetCtx:      gadgetCtx,
		globalParams:   o.globalParams,
		instanceParams: instanceParams,
		paramValues:    instanceParamValues,
	}

	err = instance.init(gadgetCtx)
	if err != nil {
		return nil, err
	}

	if len(instance.imageOperatorInstances) == 0 {
		return nil, nil
	}

	return instance, nil
}

func (o *OciHandlerInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	return o.extraParams
}

func checkBuilderVersion(manifest *v1.Manifest, logger logger.Logger, currentVersion semver.Version) {
	// Do not print any warning if this is a prerelease to avoid annoying developers
	if len(currentVersion.Pre) > 0 {
		return
	}

	builderVersionAnn := manifest.Annotations[builderVersionAnnotation]
	if builderVersionAnn == "" {
		logger.Warnf("Builder version not found in the gadget image. Gadget could be incompatible")
		return
	}

	builderVersion, err := semver.ParseTolerant(builderVersionAnn)
	if err != nil {
		// it could happen on development versions
		logger.Debugf("parsing builder version: %s", err)
		return
	}

	if !builderVersion.EQ(currentVersion) {
		logger.Warnf("This gadget was built with ig %s and it's being run with v%s. Gadget could be incompatible",
			builderVersionAnn, currentVersion)
	}
}

func constructTempConfig(ann string) (map[string]any, int, error) {
	annInfo := strings.Split(ann, ":")
	if len(annInfo) > 2 && strings.Contains(annInfo[1], "=") {
		// the case when the annotation value contains a colon
		annInfo[1] = strings.Join(annInfo[1:], ":")
	} else if len(annInfo) != 2 {
		return nil, 0, fmt.Errorf("annotation %q must be in subject:assignment format", ann)
	}

	if slices.Contains(annInfo, "") {
		return nil, 0, fmt.Errorf("annotation %q has empty subject or assignment", ann)
	}

	annotation := strings.SplitN(annInfo[1], "=", 2)
	if len(annotation) != 2 {
		return nil, 0, fmt.Errorf("annotation %q must contain a key=value pair", ann)
	}
	if annotation[0] == "" {
		return nil, 0, fmt.Errorf("annotation %q has empty key", ann)
	}

	subject := strings.Split(annInfo[0], ".")

	if slices.Contains(subject, "") {
		return nil, 0, fmt.Errorf("annotation %q has empty field or subfield name", ann)
	}

	if len(subject) > 2 {
		subject[1] = strings.Join(subject[1:], ".")
		subject = subject[:2]
	}

	switch len(subject) {
	case 1:
		// data source
		tmpConfig := map[string]any{
			"datasources": map[string]any{
				annInfo[0]: map[string]any{
					"annotations": map[string]any{
						annotation[0]: annotation[1],
					},
				},
			},
		}
		viper.Set("a", "b")
		return tmpConfig, 1, nil

	case 2:
		// field
		tmpConfig := map[string]any{
			"datasources": map[string]any{
				subject[0]: map[string]any{
					"fields": map[string]any{
						subject[1]: map[string]any{
							"annotations": map[string]any{
								annotation[0]: annotation[1],
							},
						},
					},
				},
			},
		}
		return tmpConfig, 2, nil
	}
	return nil, 0, fmt.Errorf("invalid annotation %q", ann)
}

func (o *OciHandlerInstance) init(gadgetCtx operators.GadgetContext) error {
	if len(gadgetCtx.ImageName()) == 0 {
		return fmt.Errorf("imageName empty")
	}

	var secretBytes []byte

	// TODO: move to a place without dependency on k8s
	if pullSecretParam := o.globalParams.Get(pullSecret); pullSecretParam != nil {
		pullSecretString := o.globalParams.Get(pullSecret).AsString()

		if pullSecretString != "" {
			var err error
			k8sClient, err := k8sutil.NewClientset("")
			if err != nil {
				return fmt.Errorf("creating new k8s clientset: %w", err)
			}
			// TODO: Namespace is still hardcoded
			secretBytes, err = getPullSecret(pullSecretString, "gadget", k8sClient)
			if err != nil {
				return err
			}
		}
	}

	imgOpts := &oci.ImageOptions{
		AuthOptions: oci.AuthOptions{
			AuthFile:           o.globalParams.Get(authfileParam).AsString(),
			SecretBytes:        secretBytes,
			InsecureRegistries: o.globalParams.Get(insecureRegistriesParam).AsStringSlice(),
			DisallowPulling:    o.globalParams.Get(disallowPulling).AsBool(),
		},
		VerifyOptions: oci.VerifyOptions{
			VerifyPublicKey: o.globalParams.Get(verifyImage).AsBool(),
			PublicKeys:      o.globalParams.Get(publicKeys).AsStringSlice(),
		},
		AllowedGadgetsOptions: oci.AllowedGadgetsOptions{
			AllowedGadgets: o.globalParams.Get(allowedGadgets).AsStringSlice(),
		},
		Logger: gadgetCtx.Logger(),
	}

	gadgetCtx.Logger().Debugf("image options: %+v", imgOpts)

	target := gadgetCtx.OrasTarget()
	// If the target wasn't explicitly set, use the local store. In this case we
	// need to be sure the image is available.
	if target == nil {
		// Make sure the image is available, either through pulling or by just accessing a local copy
		// TODO: add security constraints (e.g. don't allow pulling - add GlobalParams for that)
		err := oci.EnsureImage(gadgetCtx.Context(), gadgetCtx.ImageName(),
			imgOpts, o.instanceParams.Get(pullParam).AsString())
		if err != nil {
			return fmt.Errorf("ensuring image: %w", err)
		}
	}

	manifest, err := oci.GetManifestForHost(gadgetCtx.Context(), target, gadgetCtx.ImageName())
	if err != nil {
		return fmt.Errorf("getting manifest: %w", err)
	}

	log := gadgetCtx.Logger()
	checkBuilderVersion(manifest, log, version.Version())

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

	for _, ann := range o.instanceParams.Get(annotate).AsStringSlice() {
		if len(ann) == 0 {
			continue
		}
		tmpConfig, lenSubject, err := constructTempConfig(ann)
		if err != nil {
			return err
		}

		err = viper.MergeConfigMap(tmpConfig)
		if err != nil {
			return fmt.Errorf("adding annotation %q: %w", ann, err)
		}

		switch lenSubject {
		case 1:
			log.Debugf("ds annotation %q added", ann)
		case 2:
			log.Debugf("field annotation %q added", ann)
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
			return fmt.Errorf("instantiating operator %q: %w", op.Name(), err)
		}
		if opInst == nil {
			log.Debugf("> skipped %s", op.Name())
			continue
		}
		o.imageOperatorInstances = append(o.imageOperatorInstances, opInst)
	}

	if len(o.imageOperatorInstances) == 0 {
		return nil
	}

	// add extra info if requested
	if gadgetCtx.ExtraInfo() {
		err := addExtraInfo(gadgetCtx, metadata, manifest)
		if err != nil {
			return fmt.Errorf("adding extra info: %w", err)
		}
	}

	extraParams := make([]*api.Param, 0)
	for _, opInst := range o.imageOperatorInstances {
		err := opInst.Prepare(o.gadgetCtx)
		if err != nil {
			return fmt.Errorf("preparing operator %q: %w", opInst.Name(), err)
		}

		// Add gadget params prefixed with operators' name
		extraParams = append(extraParams, opInst.ExtraParams(gadgetCtx).AddPrefix(opInst.Name())...)
	}

	o.extraParams = extraParams
	return nil
}

func (o *OciHandlerInstance) Start(gadgetCtx operators.GadgetContext) error {
	started := []operators.ImageOperatorInstance{}

	for _, opInst := range o.imageOperatorInstances {
		preStart, ok := opInst.(operators.PreStart)
		if !ok {
			continue
		}
		err := preStart.PreStart(gadgetCtx)
		if err != nil {
			return fmt.Errorf("pre-starting operator %q: %w", opInst.Name(), err)
		}
	}

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

func (o *OciHandlerInstance) PreStop(gadgetCtx operators.GadgetContext) error {
	for _, opInst := range o.imageOperatorInstances {
		preStop, ok := opInst.(operators.PreStop)
		if !ok {
			continue
		}
		err := preStop.PreStop(gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("pre-stopping operator %q: %v", opInst.Name(), err)
		}
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

	for _, opInst := range o.imageOperatorInstances {
		postStop, ok := opInst.(operators.PostStop)
		if !ok {
			continue
		}
		err := postStop.PostStop(gadgetCtx)
		if err != nil {
			o.gadgetCtx.Logger().Errorf("post-stopping operator %q: %v", opInst.Name(), err)
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
	globalParams           *params.Params
	instanceParams         *params.Params
}

func (o *OciHandlerInstance) Name() string {
	return "oci"
}

func (o *ociHandler) Priority() int {
	return -1000
}

// OciHandler is a singleton of ociHandler
var OciHandler = &ociHandler{}
