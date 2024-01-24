// Copyright 2023-2024 The Inspektor Gadget authors
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

package tracer

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/btf"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

// getAnyMapElem returns any element of a map. If the map is empty, it returns nil, nil.
func getAnyMapElem[K comparable, V any](m map[K]V) (*K, *V) {
	for k, v := range m {
		return &k, &v
	}
	return nil, nil
}

func getEventTypeBTF(progContent []byte, metadata *metadatav1.GadgetMetadata) (*btf.Struct, error) {
	spec, err := loadSpec(progContent)
	if err != nil {
		return nil, err
	}

	switch {
	case len(metadata.Tracers) > 0:
		_, tracer := getAnyMapElem(metadata.Tracers)
		var valueStruct *btf.Struct
		if err := spec.Types.TypeByName(tracer.StructName, &valueStruct); err != nil {
			return nil, fmt.Errorf("finding struct %q in eBPF object: %w", tracer.StructName, err)
		}

		return valueStruct, nil
	case len(metadata.Snapshotters) > 0:
		var btfStruct *btf.Struct
		_, snapshotter := getAnyMapElem(metadata.Snapshotters)
		if err := spec.Types.TypeByName(snapshotter.StructName, &btfStruct); err != nil {
			return nil, err
		}
		return btfStruct, nil
	case len(metadata.Toppers) > 0:
		_, topper := getAnyMapElem(metadata.Toppers)
		var valueStruct *btf.Struct
		if err := spec.Types.TypeByName(topper.StructName, &valueStruct); err != nil {
			return nil, fmt.Errorf("finding struct %q in eBPF object: %w", topper.StructName, err)
		}

		return valueStruct, nil
	default:
		return nil, fmt.Errorf("the gadget doesn't provide any compatible way to show information")
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
