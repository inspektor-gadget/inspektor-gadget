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

package signature

import (
	"context"
	"errors"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/cosign"
)

type Exporter interface {
	ExportSigningInformation(ctx context.Context, src oras.ReadOnlyTarget, dst oras.Target, desc ocispec.Descriptor) error
}

type SignatureExporter struct {
	exporters map[string]Exporter
}

var DefaultSignatureExporter = SignatureExporter{
	exporters: map[string]Exporter{
		"cosign":  &cosign.Exporter{},
	},
}

func (e *SignatureExporter) ExportSigningInformation(ctx context.Context, src oras.ReadOnlyTarget, dst oras.Target, desc ocispec.Descriptor) error {
	if len(e.exporters) == 0 {
		return errors.New("no exporting method available")
	}

	errs := make([]error, 0)
	for method, exporter := range e.exporters {
		err := exporter.ExportSigningInformation(ctx, src, dst, desc)
		if err == nil {
			return nil
		}

		errs = append(errs, fmt.Errorf("exporting signing information with %s: %w", method, err))
	}

	return errors.Join(errs...)
}
