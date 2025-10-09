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
	"fmt"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

type Puller struct{} // Empty type only to respect the interface.

func pullCosignSigningInformation(ctx context.Context, repo *remote.Repository, signingInfoTag string, imageStore oras.Target) error {
	if _, err := oras.Copy(ctx, repo, signingInfoTag, imageStore, signingInfoTag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("copying index tag %q: %w", signingInfoTag, err)
	}

	return nil
}

func (c *Puller) PullSigningInformation(ctx context.Context, repo *remote.Repository, imageStore oras.Target, digest string) error {
	signingInfoTag, err := craftCosignSignatureTag(digest)
	if err != nil {
		return fmt.Errorf("crafting cosign signature tag: %w", err)
	}

	return pullCosignSigningInformation(ctx, repo, signingInfoTag, imageStore)
}
