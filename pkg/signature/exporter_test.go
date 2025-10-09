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
	"testing"

	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
)

func TestExportSigningInformation(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		src string
		dst string
	}

	tests := map[string]testDefinition{
		"cosign_signed_image": {
			src: "ghcr.io/inspektor-gadget/gadget/trace_open@sha256:7ecd35cc935edb56c7beb1077e4ca1aabdd1d4e4429b0df027398534d6da9fe6",
			dst: "ttl.sh/trace_open:cosign-export-unit-test",
		},
	}

	for name, test := range tests {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			store, repo, ref := createTestPrerequisities(t, test.src)
			destStore, _, destRef := createTestPrerequisities(t, test.dst)

			// Pull the image.
			desc, err := oras.Copy(context.Background(), repo, ref.String(), store, ref.String(), oras.DefaultCopyOptions)
			require.NoError(t, err)

			err = DefaultSignaturePuller.PullSigningInformation(ctx, repo, store, desc.Digest.String())
			require.NoError(t, err)

			// Push the image
			desc, err = oras.Copy(ctx, store, ref.String(), destStore, destRef.String(), oras.DefaultCopyOptions)
			require.NoError(t, err)

			err = DefaultSignatureExporter.ExportSigningInformation(ctx, store, destStore, desc)
			require.NoError(t, err)
		})
	}
}
