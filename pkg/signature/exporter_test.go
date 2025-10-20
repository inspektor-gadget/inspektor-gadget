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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content/oci"
)

func TestExportSigningInformation(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		src       string
		dst       string
		searchFor string
	}

	tests := map[string]testDefinition{
		"cosign_legacy_signed_image": {
			src:       "ttl.sh/signed_with_cosign_legacy:latest",
			dst:       "signed_with_cosign_legacy",
			searchFor: "application/vnd.dev.cosign.simplesigning.v1+json",
		},
		"cosign_oci11_signed_image": {
			src:       "ttl.sh/signed_with_cosign_oci11:latest",
			dst:       "signed_with_cosign_oci11",
			searchFor: "application/vnd.dev.cosign.simplesigning.v1+json",
		},
		"notation_signed_image": {
			src:       "ttl.sh/signed_with_notation:latest",
			dst:       "signed_with_cosign_notation",
			searchFor: "io.cncf.notary.signingAgent",
		},
	}

	srcStore, err := oci.New(filepath.Join("testdata", "oci-store"))
	require.NoError(t, err)

	for name, test := range tests {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()
			dstStore, err := oci.New(tempDir)
			require.NoError(t, err)

			ctx := context.Background()
			desc, err := srcStore.Resolve(ctx, test.src)
			require.NoError(t, err)

			err = DefaultSignatureExporter.ExportSigningInformation(ctx, srcStore, dstStore, desc)
			require.NoError(t, err)

			found := false
			err = filepath.WalkDir(tempDir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				content, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				if strings.Contains(string(content), test.searchFor) {
					found = true
					return fs.SkipAll
				}

				return nil
			})
			require.NoError(t, err)
			require.True(t, found)
		})
	}
}
