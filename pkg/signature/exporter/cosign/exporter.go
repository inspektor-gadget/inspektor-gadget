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

package cosign

import (
	"context"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/helpers"
)

type Exporter struct{} // Empty type only to respect the interface.

func (*Exporter) ExportSigningInformation(ctx context.Context, src oras.ReadOnlyGraphTarget, dst oras.Target, desc ocispec.Descriptor) error {
	return helpers.CopySigningInformation(ctx, src, dst, desc.Digest.String(), helpers.CraftCosignSignatureTag)
}

func (*Exporter) Name() string {
	return "cosign"
}
