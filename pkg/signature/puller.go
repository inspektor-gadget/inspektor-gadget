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

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/cosign"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/oci11"
)

type Puller interface {
	PullSigningInformation(ctx context.Context, repo *remote.Repository, imageStore oras.Target, digest string) error
}

type SignaturePuller struct {
	pullers map[string]Puller
}

var DefaultSignaturePuller = SignaturePuller{
	pullers: map[string]Puller{
		"cosign":  &cosign.Puller{},
		"oci 1.1": &oci11.Puller{},
	},
}

func (p *SignaturePuller) PullSigningInformation(ctx context.Context, repo *remote.Repository, imageStore oras.Target, digest string) error {
	if len(p.pullers) == 0 {
		return errors.New("no pulling method available")
	}

	errs := make([]error, 0)
	for method, puller := range p.pullers {
		err := puller.PullSigningInformation(ctx, repo, imageStore, digest)
		if err == nil {
			return nil
		}

		errs = append(errs, fmt.Errorf("pulling signing information with %s: %w", method, err))
	}

	return errors.Join(errs...)
}
