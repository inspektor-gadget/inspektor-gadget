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

package bundle

import (
	"context"
	"errors"
	"fmt"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/helpers"
)

// Taken from:
// https://github.com/sigstore/cosign/blob/ee3d9fe1c55e/pkg/cosign/bundle/protobundle.go#L36
const bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

type Puller struct{} // Empty type only to respect the interface.

func (c *Puller) PullSigningInformation(ctx context.Context, repo *remote.Repository, imageStore oras.Target, digest string) error {
	return helpers.CopySigningInformation(ctx, repo, imageStore, digest, func(digest string) (string, error) {
		desc, err := imageStore.Resolve(ctx, digest)
		if err != nil {
			return "", fmt.Errorf("resolving %s: %w", digest, err)
		}

		descriptors, err := registry.Referrers(ctx, repo, desc, bundleV03MediaType)
		if err != nil {
			return "", fmt.Errorf("searching for bundle referring %q: %w", digest, err)
		}

		if len(descriptors) == 0 {
			return "", errors.New("no bundle found")
		}

		if len(descriptors) > 1 {
			return "", errors.New("image with several bundles are not supported")
		}

		signingInfoTag := descriptors[0].Digest.String()

		return signingInfoTag, nil
	})
}
