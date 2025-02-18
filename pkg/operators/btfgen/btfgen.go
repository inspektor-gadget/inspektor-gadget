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

package btfgenoperator

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf/btf"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

const (
	btfMediaType   = "application/vnd.gadget.btfgen.v1+binary"
	kernelTypesVar = "kernelTypes"
)

var kernelHasBTF func() bool = sync.OnceValue(func() bool {
	_, err := btf.LoadKernelSpec()
	return err == nil
})

type btfgenOperator struct{}

func (o *btfgenOperator) Name() string {
	return "btfgen"
}

func (o *btfgenOperator) Description() string {
	return "Enables to run gadget on kernels without BTF information by using BTF types generated with btfgen"
}

func (o *btfgenOperator) InstantiateImageOperator(
	gadgetCtx operators.GadgetContext,
	target oras.ReadOnlyTarget,
	desc ocispec.Descriptor,
	paramValues api.ParamValues,
) (operators.ImageOperatorInstance, error) {
	logger := gadgetCtx.Logger()

	// If the kernel exposes BTF; nothing to do
	if kernelHasBTF() {
		logger.Debugf("kernel provides BTF, nothing to do on btfgen operator")
		return nil, nil
	}

	return &btfgenOperatorInstance{
		target: target,
		desc:   desc,
	}, nil
}

type btfgenOperatorInstance struct {
	target oras.ReadOnlyTarget
	desc   ocispec.Descriptor
}

func (i *btfgenOperatorInstance) Name() string {
	return "btfgenInstance"
}

func (i *btfgenOperatorInstance) Prepare(gadgetCtx operators.GadgetContext) error {
	info, err := btfgen.GetOSInfo()
	if err != nil {
		return fmt.Errorf("getting OS info: %w", err)
	}

	r, err := oci.GetContentFromDescriptor(gadgetCtx.Context(), i.target, i.desc)
	if err != nil {
		return fmt.Errorf("getting ebpf binary: %w", err)
	}
	defer r.Close()

	btfFileName := fmt.Sprintf("%s/%s/%s/%s.btf", info.ID, info.VersionID, info.Arch, info.Kernel)
	btfBytes, err := getBTFFile(r, btfFileName)
	if err != nil {
		return fmt.Errorf("getting BTF file: %w", err)
	}

	btfSpec, err := btf.LoadSpecFromReader(bytes.NewReader(btfBytes))
	if err != nil {
		return fmt.Errorf("loading BTF spec: %w", err)
	}

	// save the kernel types to be used by the ebpf operator when loading bpf the spec.
	gadgetCtx.SetVar(kernelTypesVar, btfSpec)

	return nil
}

func (i *btfgenOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (i *btfgenOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func getBTFFile(r io.Reader, filename string) ([]byte, error) {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("BTF file %q not found", filename)
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}

		if hdr.Name == filename {
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("reading BTF: %w", err)
			}

			return b, nil
		}
	}
}

func (i *btfgenOperatorInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	return nil
}

func init() {
	operators.RegisterOperatorForMediaType(btfMediaType, &btfgenOperator{})
}
